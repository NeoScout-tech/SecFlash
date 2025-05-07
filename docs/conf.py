import os
import sys
sys.path.insert(0, os.path.abspath('..'))

project = 'SecFlash'
copyright = '2025'
author = 'saikonohack'

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
    'sphinx.ext.viewcode',
    'sphinx.ext.githubpages',
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

autodoc_member_order = 'bysource'
autodoc_typehints = 'description' 