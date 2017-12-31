# How to run

1. 【run directly with python】
	python runserver.py

2. 【uwsgi from python】
	pip install uwsgi
	uwsgi --http-socket 0.0.0.0:8080 -w 'ipsrv:app'

3. 【uwsgi service】
	uwsgi --http-socket 0.0.0.0:8080 --plugin python -w 'ipsrv:app'

	or use
	use uwsgi.ini
