Development
===========

Development Environment Setup
---------------------------

1. Clone the repository:

   .. code-block:: bash

       git clone https://github.com/yourusername/secflash.git
       cd secflash

2. Install development dependencies:

   .. code-block:: bash

       poetry install

Development Tools
---------------

The project uses several development tools:

* Poetry for dependency management
* pytest for testing
* black for code formatting
* isort for import sorting
* mypy for type checking
* flake8 for linting

Running Tests
-----------

Run the test suite:

.. code-block:: bash

    poetry run pytest

Type Checking
------------

Run type checking:

.. code-block:: bash

    poetry run mypy secflash tests

Code Formatting
-------------

Format code:

.. code-block:: bash

    poetry run black secflash tests
    poetry run isort secflash tests

Building Documentation
-------------------

Build the documentation:

.. code-block:: bash

    poetry run sphinx-build -b html docs docs/_build/html 