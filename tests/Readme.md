# Test Guide

## Requirements
### Base
- Python 3.7

### Packages
- PyTest https://pytest.org
- pytest-testdox https://github.com/renanivo/pytest-testdox

## Run Tests

To run the tests, add the tiffy main directory to your PYTHONPATH variable and 
simply call `pytest` from tiffys main directory.

```bash
$ export PYTHONPATH=`pwd`:$PYTHONPATH
$ pytest
```

## Run single test modules

it is possible to only run a single test module by passing the path to the test file to pytest.

```bash
$ pytest tests/test_fileHelper.py           #tests File reading/writing

$ pytest tests/test_iocHelper.py            #tests generation of iocs from observations

$ pytest tests/test_MISPHelper.py           #tests conversion of TIE ioc's to MISP Event

$ pytest tests/test_TIELoader.py            #tests deduplication of observations

$ pytest tests/test_tiffy.py                #tests cli parameter handling
```
