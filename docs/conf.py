import os

import sdv

project = u'stix-validator'
copyright = u'2015, The MITRE Corporation'
version = sdv.__version__
release = version

extensions = [
    'sphinx.ext.autodoc',
    'sphinxcontrib.napoleon',
]

templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'

rst_prolog = """
**Version**: {0}
""".format(release)

exclude_patterns = ['_build']
pygments_style = 'sphinx'

on_rtd = os.environ.get('READTHEDOCS', None) == 'True'
if not on_rtd:  # only import and set the theme if we're building docs locally
    import sphinx_rtd_theme
    html_theme = 'sphinx_rtd_theme'
    html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]
else:
    html_theme = 'default'

latex_elements = {}
latex_documents = [
  ('index', 'stix-validator.tex', u'stix-validator Documentation',
   u'The MITRE Corporation', 'manual'),
]
