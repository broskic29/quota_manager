# quota-manager
Python application for OpenWRT quota management and throttling.

Meant to run as a service on an OpenWRT-enabled router to manage network traffic,
providing dynamic data control on a per-user basis.

Paired with: https://github.com/broskic29/openwrt-builder

To run:
pipenv run quota_manager

[Pytest]
To run pytest unit tests only:
pipenv run pytest -q

To run a specific unit test:
pipenv run pytest -q {test_name.py}

To run integration only (already as root):
pipenv run pytest -m integration -q

To run a specific integration test (already as root): 
pipenv run pytest -m integration -q {test_name.py}
