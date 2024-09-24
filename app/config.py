import urllib

class Config:
    SECRET_KEY = 'your_secret_key_here'
    params = 'DRIVER={ODBC Driver 17 for SQL Server};SERVER=DESKTOP-EO48R9P\\SQLEXPRESS;DATABASE=tams;Trusted_Connection=yes;'
    SQLALCHEMY_DATABASE_URI = f"mssql+pyodbc:///?odbc_connect={urllib.parse.quote_plus(params)}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False