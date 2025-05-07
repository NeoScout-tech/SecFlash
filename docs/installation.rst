Installation
============

Requirements
-----------

* Python 3.8 or higher
* Poetry for dependency management
* NVD API key (optional, but recommended)

Installation Steps
----------------

1. Clone the repository:

   .. code-block:: bash

       git clone https://github.com/yourusername/secflash.git
       cd secflash

2. Install dependencies using Poetry:

   .. code-block:: bash

       poetry install

Environment Setup
--------------

1. Create a `.env` file in the project root:

   .. code-block:: text

       NVD_API_KEY=your_api_key_here
       DATABASE_URL=sqlite:///vulnerabilities.db

2. Activate the virtual environment:

   .. code-block:: bash

       poetry shell

Verifying Installation
-------------------

Run the test suite to verify the installation:

.. code-block:: bash

    poetry run pytest 