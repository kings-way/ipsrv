# How to run
----
### Prerequisites
Install GeoIP database update tool and download the database.

	apt install geoipupdate
	geoipupdate -v

----
### 1. **run directly with python**

	python runserver.py

### 2. uwsgi from python

	pip install uwsgi
	uwsgi --http-socket 0.0.0.0:8080 -w 'ipsrv:app'
	

### 3. uwsgi from APT
* **run with command**
	
		apt install uwsgi uwsgi-plugin-python
		uwsgi --http-socket 0.0.0.0:8080 --plugin python -w 'ipsrv:app'

* **uwsgi service**
	
		apt install uwsgi uwsgi-plugin-python
		
		# Configure uwsgi
		cp uwsgi.ini /etc/uwsgi/apps-available
		ln -s /etc/uwsgi/apps-available/uwsgi.ini /etc/uwsgi/apps-enabled/
		service uwsgi restart
		
		# Configure nginx
		....
