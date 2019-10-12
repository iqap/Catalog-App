# Catalog App

This is project is one project in Udacity full stack program

## Getting Started

* First login to Google Console in [Google Cloud Platform](https://console.cloud.google.com/)
* Create New Project
* Go to API & Services dashboard
* Select Credentials
* Create new Credentials of the type (OAuth client ID)
* Select the type (Web application) 
* Put (http://localhost:5000) as Authorized JavaScript origins 
* Put (http://localhost:5000, http://localhost:5000/login, http://localhost:5000/gconnect) as Authorized redirect URIs
* Copy Client ID to data-clientid in (templates/login.html)
* Save and download the Json
* Replace the the json you download with client_secrets.json
* Run the following command to create the database
```
python database_setup.py
python add_dummy.py 
```
* Note: if there are missing modules, install then run the commands
* Run the Application
```
python project.py
```

## How to use Catalog App

* Only the logged-in user can add categories and items.
* Every user can only edit items and categories created by him.
* JSON endpoint:
```
/catalog/JSON
/catalog/<category name>/JSON
/catalog/<category name>/<item name>/JSON
```