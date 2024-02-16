# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# builtin
import os
import collections

# external
from lxml import etree

# internal
from sdv import errors, utils, xmlconst

# relative
from . import base


class XmlSchemaError(base.ValidationError):
    """Represents an XML Schema validation error.

    Args:
        error: An error returned from ``etree`` XML Schema validation error
            log.

    Attributes:
        message: The XML validation error message.

    """
    def __init__(self, error):
        super(XmlSchemaError, self).__init__()

        if error:
            self.message = str(error)
        else:
            self.message = None

    @property
    def line(self):
        """Returns the line number associated with the error."""
        if not self.message:
            return None

        try:
            # libxml2 schema validation errors are tokenized by colons
            tokenized = self.message.split(":")
            return int(tokenized[1])
        except (IndexError, TypeError, ValueError):
            return None

    def as_dict(self):
        """Returns a dictionary representation.

        Keys:
            * ``'message'``: The error message
            * ``'line'``: The line number associated with the error
        """
        return {'message':self.message, 'line': self.line}

    def __str__(self):
        return str(self.message)


class XmlValidationResults(base.ValidationResults):
    """Results of XML schema validation. Returned from
    :meth:`XmlSchemaValidator.validate`.

    Args:
        is_valid: The validation result.
        errors: A list of strings reported from the XML validation engine.

    Attributes:
        is_valid: ``True`` if the validation was successful and ``False``
            otherwise.

    """
    def __init__(self, is_valid, errors=None):
        super(XmlValidationResults, self).__init__(is_valid)
        self.errors = errors

    @property
    def errors(self):
        """"A list of :class:`XmlSchemaError` validation errors."""
        return self._errors

    @errors.setter
    def errors(self, value):
        if not value:
            self._errors = []
        elif utils.is_iterable(value):
            self._errors = [XmlSchemaError(x) for x in value]
        else:
            self._errors = [XmlSchemaError(value)]

    def as_dict(self):
        """A dictionary representation of the :class:`.XmlValidationResults`
        instance.

        Keys:
            * ``'result'``: The validation results (``True`` or ``False``)
            * ``'errors'``: A list of validation errors.

        Returns:
            A dictionary representation of an instance of this class.

        """
        d = super(XmlValidationResults, self).as_dict()

        if self.errors:
            d['errors'] = [x.as_dict() for x in self.errors]

        return d


class XmlSchemaValidator(object):
    """Validates XML instance documents.

    Note:
        If validating against a single XML schema document, use
        ``lxml.etree.XMLSchema`` instead.

    Args:
        schema_dir: A directory of schema files used to validate XML instance
            documents.

    Attributes:
        OVERRIDE_SCHEMALOC: Overrides the schemalocation for a given namespace
            that may be discovered when walking `schema_dir`. This does not
            alter the schemalocation of namespaces declared by
            ``xsi:schemalLocation`` attributes if validating via
            ``xsi:schemaLocation``.

    """
    OVERRIDE_SCHEMALOC = {}

    def __init__(self, schema_dir=None):
        self._schemalocs = self._map_schemalocs(schema_dir)

    def _get_includes(self, fp, root):
        """Returns a list of ``xs:include`` targets found within `root`.

        The returned list contains paths to the ``xs:include`` targets. The
        file paths are absolute.

        Note:
            This assumes all includes point to local schemas. Remote schema
            locations will not be parsed correctly!

        Args:
            fp: The file path to `root`. This is used to determine the path
                to the included schema if the include path is relative.
            root: An etree._Element representation of the schema.

        Returns:
            A list of file paths to included schemas.

        """
        xs_includes = root.findall(xmlconst.TAG_XS_INCLUDE)
        dir_ = os.path.dirname(fp)

        includes = []
        for include in xs_includes:
            loc = include.attrib['schemaLocation']  # NOT xsi:schemaLocation!

            # If the path is relative, get the absolute path
            if os.path.isabs(loc):
                locpath = loc
            else:
                locpath = os.path.abspath(os.path.join(dir_, loc))

            includes.append(locpath)

        return includes

    def _build_include_graph(self, schema_paths):
        """Builds a graph of ``xs:include`` directive sources and targets for
        the schemas contained by the `schema_paths` list.

        Args:
            schema_paths: A list of schema file paths

        Returns:
            A graph representing ``xs:include`` statements found within the
            schemas in `schema_paths`.

        """
        graph = collections.defaultdict(list)

        for fp in schema_paths:
            root = utils.get_etree_root(fp)
            includes = self._get_includes(fp, root)
            graph[fp].extend(includes)

        return graph

    def _is_included(self, graph, fp):
        """Returns ``True`` if the schema at `fp` was included by any other
        schemas in `graph`.

        """
        return any(fp in includes for includes in graph.values())

    def _get_include_root(self, ns, list_schemas):
        """Attempts to determine the "root" schema for a targetNamespace.

        This builds a graph of ``xs:include`` directive sources and targets
        and attempts to find a common base for all includes.

        Note:
            If no schemas in `list_schemas` ``xs:include`` another schema,
            then ``list_schemas[0]`` is returned. This occurs when duplicate
            schemas (or different versions of the same schema that define the
            same namespace) were encountered in the initialization schema
            directory.

        Args:
            ns: The target namespace
            list_schemas: A list of schemas which exist or define the
                target namespace.

        Returns:
            A path to the root schema for the input `ns`.

        """
        graph = self._build_include_graph(list_schemas)

        if all(not(x) for x in graph.values()):
            return list_schemas[0]

        for fp in graph:
            has_ancestors = self._is_included(graph, fp)
            has_children  = len(graph[fp]) > 0

            if has_children and not has_ancestors:
                return fp

        msg = "Unable to determine base schema for %s" % ns
        raise errors.XMLSchemaIncludeError(msg)

    def _process_includes(self, imports):
        """Attempts to resolve cases where multiple schemas declare the same
        ``targetNamespace`` value. This is due to the use of the ``xs:include``
        directive, which can be found in OASIS CIQ schemas along with others.

        This is done by building an ``xs:include`` graph, and returning the
        root of that graph.

        Note:
            This method is flawed! This assumes that the ``xs:include`` graph
            is really a tree, and has a root which can be imported and used
            to validate all instance data which belongs to its namespace.

            A better way may be to programatically combine all "split" schemas
            within a single schema document and map the targetNamespace to that
            combined schema document.

        Args:
            imports: A dictionary of namespaces to a list of schema file
                paths. Most often, this list will have only one file path
                in it.

        Returns:
            A dictionary of schema targetNamespaces to a single schema file
            path.

        """
        processed = {}

        for ns, schemas in imports.items():
            if len(schemas) > 1:
                base_schema = self._get_include_root(ns, schemas)
                processed[ns] = base_schema
            else:
                processed[ns] = schemas[0]

        return processed

    def _walk_schemas(self, schema_dir):
        """Walks the `schema_dir` directory and builds a dictionary of
        schema ``targetNamespace`` values to a list of schema file paths.

        Because multiple schemas can declare the same ``targetNamespace``
        value, the ``value`` portion of the returned dictionary is a ``list``.

        Note:
            This method attempts to resolve issues where the same schema
            exists in two or more locations under `schema_dir` by keeping
            a record of visited target namespaces and filenames. If the same
            filename:targetNS (not file path) pair has been visited already,
            the file is not added to the schemalocation dictionary.

        Returns:
            A dictionary of  schema ``targetNamespace`` values to a list of
            schema file paths.

        """
        seen = []
        schemalocs = collections.defaultdict(list)

        for top, _, files in os.walk(schema_dir):
            for fn in files:
                if not fn.endswith('.xsd'):
                    continue

                fp = os.path.abspath(os.path.join(top, fn))
                target_ns = utils.get_target_ns(fp)

                if (target_ns, fn) in seen:
                    continue

                schemalocs[target_ns].append(fp)
                seen.append((target_ns, fn))

        for ns, loc in self.OVERRIDE_SCHEMALOC.items():
            schemalocs[ns] = [loc]

        return schemalocs

    def _map_schemalocs(self, schema_dir):
        """Walks the `schema_dir` directory and builds a dictionary which maps
        schema targetNamespace values to schema file paths.

        If `schema_dir` is ``None``, this function returns immediately.

        Returns:
            A dictionary mapping schema ``targetNamespace`` values to the
            schema file path.

        Raises:
            .XMlSchemaIncludeError: If an error occurs while processing
                ``xs:include`` directives.

        """
        if not schema_dir:
            return

        schemalocs = self._walk_schemas(schema_dir)
        schemalocs = self._process_includes(schemalocs)

        return schemalocs

    def _parse_schemaloc(self, root):
        """Parses the ``xsi:schemaLocation`` attribute found on `root`.

        Returns:
            A dictionary of namespaces to schema locations.

        Raises:
            .XMLSchemaImportError: If `root` did not contain an
                ``xsi:schemaLocation`` attribute.

        """
        if xmlconst.TAG_SCHEMALOCATION in root.attrib:
            imports = utils.get_schemaloc_pairs(root)
            return dict(imports)

        msg = ("Cannot validate using xsi:schemaLocation. The "
               "xsi:schemaLocation attribute was not found on the input "
               "document")
        raise errors.XMLSchemaImportError(msg)

    def _get_required_schemas(self, root):
        """Retrieve all the namespaces and schemalocations needed to validate
        `root`.

        Args:
            root: An etree._Element XML document.

        Returns:
            A dictionary mapping namespaces to schemalocations.

        """
        def _get_schemalocs(node):
            schemalocs = {}

            for ns in node.nsmap.values():
                if ns not in self._schemalocs:
                    continue

                schemalocs[ns] = self._schemalocs[ns]
            return schemalocs

        imports = {}
        for elem in root.iter():
            schemalocs = _get_schemalocs(elem)
            imports.update(schemalocs)

        return imports

    def _build_required_imports(self, doc, schemaloc=False):
        root = utils.get_etree_root(doc)

        if schemaloc:
            return self._parse_schemaloc(root)

        return self._get_required_schemas(root)

    def _build_uber_schema(self, doc, schemaloc=False):
        """Builds a schema which is made up of ``xs:import`` directives for
        each schema required to validate `doc`.

        If schemaloc is ``True``, the ``xsi:schemaLocation`` attribute values
        are used to create the ``xs:import`` directives. If ``False``, the
        initialization schema directory is used.

        Returns:
            An ``etree.XMLSchema`` instance used to validate `doc`.

        Raise:
            .XMLSchemaImportError: If an error occurred while building the
                dictionary of namespace to schemalocation mappings used to
                drive the uber schema creation.

        """
        root = utils.get_etree_root(doc)
        imports = self._build_required_imports(root, schemaloc)

        if not imports:
            raise errors.XMLSchemaImportError(
                "Cannot validate document. Error occurred while determining "
                "schemas required for validation."
            )

        xsd = etree.fromstring(
            """
            <xs:schema
                xmlns:xs="http://www.w3.org/2001/XMLSchema"
                targetNamespace="http://stix.mitre.org/tools/validator"
                elementFormDefault="qualified"
                attributeFormDefault="qualified"/>
            """
        )

        for ns, loc in imports.items():
            loc = loc.replace("\\", "/")
            attrib = {'namespace': ns, 'schemaLocation':loc}
            import_ = etree.Element(xmlconst.TAG_XS_IMPORT, attrib=attrib)
            xsd.append(import_)

        return etree.XMLSchema(xsd)

    def validate(self, doc, schemaloc=False):
        """Validates an XML instance document.

        Args:
            doc: An XML instance document. This can be a filename, file-like
                object, ``etree._Element``, or ``etree._ElementTree``.
            schemaloc: If ``True``, the document will be validated using the
                ``xsi:schemaLocation`` attribute found on the instance
                document root.

        Returns:
            An instance of
            :class:`.XmlValidationResults`.

        Raises:
            .ValidationError: If the class was not initialized with a
                schema directory and `schemaloc` is ``False`` or if there are
                any issues parsing `doc`.
            .XMLSchemaIncludeError: If an error occurs while processing the
                schemas required for validation.
            .XMLSchemaIncludeError: If an error occurs while processing
                ``xs:include`` directives.

        """
        if not (schemaloc or self._schemalocs):
            raise errors.ValidationError(
                "No schemas to validate against! Try instantiating "
                "XmlValidator with use_schemaloc=True or setting the "
                "schema_dir param in __init__"
            )

        root = utils.get_etree_root(doc)
        xsd = self._build_uber_schema(root, schemaloc)
        is_valid = xsd.validate(root)

        return XmlValidationResults(is_valid, xsd.error_log)


__all__ = [
    'XmlSchemaValidator',
    'XmlValidationResults',
    'XmlSchemaError'
]
