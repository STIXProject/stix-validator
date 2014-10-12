# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import os
from collections import defaultdict
from lxml import etree

from sdv import (_BaseValidationResults, ValidationError)
import sdv.utils as utils

NS_XML_SCHEMA_INSTANCE = "http://www.w3.org/2001/XMLSchema-instance"
NS_XML_SCHEMA = "http://www.w3.org/2001/XMLSchema"
TAG_XS_INCLUDE = "{%s}include" % (NS_XML_SCHEMA)
TAG_XS_IMPORT = "{%s}import" % (NS_XML_SCHEMA)


class IncludeProcessError(ValidationError):
    pass


class ImportProcessError(ValidationError):
    pass


class XmlValidationResults(_BaseValidationResults):
    pass


class XmlSchemaValidator(object):
    def __init__(self, schema_dir=None):
        self._schemas = self._map_schemas(schema_dir)


    def _get_includes(self, root):
        xs_includes = root.findall(TAG_XS_INCLUDE)

        includes= []
        for include in xs_includes:
            loc = include.attrib['schemaLocation']
            fn = os.path.split(loc)[1]
            includes.append(fn)

        return includes


    def _build_include_graph(self, schema_paths):
        graph = defaultdict(list)

        for schema_path in schema_paths:
            root = utils.get_etree_root(schema_path)
            includes = self._get_includes(root)
            schema_fn = os.path.split(schema_path)[1]
            graph[schema_fn].append(includes)

        return graph


    def _is_included(self, graph, fn):
        for schema, includes in graph.iteritems():
            if fn in includes:
                return True

        return False


    def _get_include_root(self, ns, list_schemas):
        include_graph = self._build_include_graph(list_schemas)

        for fn in include_graph:
            if (not self._is_included(include_graph, fn) and
               (len(include_graph[fn]) > 0)):
                return fn

        raise IncludeProcessError(
            "Unable to determine base schema for %s" % ns
        )


    def _map_schemas(self, schema_dir):
        '''Given a directory of schemas, this builds a dictionary of schemas
        that need to be imported under a wrapper schema in order to enable
        validation. This returns a dictionary of the form
        {namespace : path to schema}.

        Keyword Arguments
        schema_dir - a directory of schema files
        '''
        if not schema_dir:
            return

        imports = defaultdict(list)
        for top, dirs, files in os.walk(schema_dir):
            for f in files:
                if f.endswith('.xsd'):
                    fp = os.path.join(top, f)
                    target_ns = utils.get_target_ns(fp)
                    imports[target_ns].append(fp)

        for ns, schemas in imports.iteritems():
            if len(schemas) > 1:
                base_schema = self._get_include_root(ns, schemas)
                imports[ns] = base_schema
            else:
                imports[ns] = schemas[0]

        return imports


    def _build_required_imports(self, doc, schemaloc=False):
        root = utils.get_etree_root(doc)
        imports = {}

        if schemaloc:
            try:
                imports = utils.get_schemaloc_pairs(root)
            except KeyError:
                raise ImportProcessError(
                    "Cannot validate using xsi:schemaLocation. The "
                    "xsi:schemaLocation attribute was not found on the input "
                    "document"
                )

        for elem in root.iter():
            for prefix, ns in elem.nsmap.iteritems():
                if ns not in self._schemas:
                    continue

                schema_location = self._schemas[ns]
                imports[ns] = schema_location

        return imports


    def _build_uber_schema(self, doc, schemaloc=False):
        root = utils.get_etree_root(doc)
        imports = self._build_required_imports(root)

        if not imports:
            raise ImportProcessError(
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

        for ns, schemaloc in imports.iteritems():
            schemaloc = schemaloc.replace("\\", "/")
            attrib = {
                'namespace': ns,
                'schemaLocation': schemaloc
            }
            import_ = etree.Element(TAG_XS_IMPORT, attrib=attrib)
            xsd.append(import_)

        return etree.XMLSchema(xsd)


    def validate(self, doc, schemaloc=False):
        '''Validates an instance documents.

        Returns a tuple of where the first item is the boolean validation
        result and the second is the validation error if there was one.

        Keyword Arguments
        instance_doc - a filename, file-like object, etree._Element, or
                       etree._ElementTree to be validated

        '''
        if not any((schemaloc, self._schemas)):
            raise ValidationError(
                "No schemas to validate against! Try instantiating "
                "XmlValidator with use_schemaloc=True or setting the "
                "schema_dir param in __init__"
            )

        root = utils.get_etree_root(doc)
        xsd = self._build_uber_schema(root, schemaloc)
        is_valid = xsd.validate(root)

        result = XmlValidationResults()
        result.is_valid = is_valid
        result.errors = [str(x) for x in xsd.error_log]

        return result

