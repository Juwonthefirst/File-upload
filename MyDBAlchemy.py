from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, String, DateTime, ForeignKey, Update
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func
from datetime import datetime
from typing import List

db = SQLAlchemy()


# class for User table that stores user data
class Users(db.Model):
	
	id: Mapped[int] = mapped_column(Integer, primary_key = True)
	username: Mapped[str] = mapped_column(String(20), unique = True, nullable = False)
	email: Mapped[str] = mapped_column(String(20), unique = True, nullable = False)
	password: Mapped[str] = mapped_column(String(20), nullable = False)
	created_at: Mapped[datetime] = mapped_column(DateTime, server_default = func.now())
	fileUploads:Mapped[List["Uploads"]] = relationship("Uploads", backref="uploader", lazy = True)
	
	
	def __repr__(self):
		return f"Users({self.username}, {self.email})"
		
	def add(self):
		db.session.add(self)
		db.session.commit()
		return f"{self.username} successfully added to database"
		
	def delete(self):
		db.session.delete(self)
		db.session.commit()
		return f"{self.username} successfully deleted from database"
		
	@classmethod
	def update_name(cls, previous_username, new_username):
		db.session.execute(Update(cls).where(cls.username == previous_username).values(username = new_username))
		db.session.commit()
		return f"{previous_username} has been changed to {new_username}"
		
	
	@classmethod
	def update_email(cls, previous_email, new_email):
		db.session.execute(Update(cls).where(cls.email == previous_email).values(email = new_email))
		db.session.commit()
		return f"{previous_email} has been changed to {new_email}"
		
		
	@classmethod
	def update_pass(cls, username, new_pass):
		db.session.execute(Update(cls).where(cls.username == username).values(password = new_pass))
		db.session.commit()
		return f"{username} password updated"
		
		
	# to fetch user details from the database			
	@classmethod		
	def fetch(cls, area, user_detail, search = None):
		if area in ["password", "username", "email"] and search in ["password", "username", "email", None]:
			if not search:
				search = area
			return db.session.execute( db.select(getattr(cls, area)).where(getattr(cls, search) == user_detail)).scalar_one_or_none()
		else:
			raise TypeError("Incorrect value used in Fetch method")	
			

#class for table to store all uploads made by a user
																
class Uploads(db.Model):
	
	id:Mapped[int] = mapped_column(Integer, primary_key = True)
	filename: Mapped[str] = mapped_column(String(), nullable = False)
	filesize:Mapped[int] = mapped_column(Integer, nullable = False)
	uploaded_at: Mapped[datetime] = mapped_column(DateTime, server_default = func.now())
	user_id: Mapped[int] = mapped_column(db.ForeignKey("users.id"), nullable = False)
	
	
	def __repr__(self):
		return f"File({self.filename}, {self.filesize})"
		
	def add(self):
		db.session.add(self)
		db.session.commit()
		return f"{self.filename} uploaded successfully"
		
	def delete(self):
		db.session.delete(self)
		db.session.commit()
		return f"{self.filename} deleted successfully"
		
	@classmethod
	def update_name(cls, previous_filename, new_filename):
		db.session.execute(Update(cls).where(cls.filename == previous_filename).values(filename = new_filename))
		db.session.commit()
		return f"{previous_filename} has been changed to {new_filename}"
		
		
	# to fetch user details from the database			
	@classmethod		
	def fetch(cls, area, user_detail, search = None):
		if area in ["filename", "filelink"] and search in ["filename", "filelink", None]:
			if not search:
				search = area
			return db.session.execute( db.select(getattr(cls, area)).where(getattr(cls, search) == user_detail)).scalar_one()
		else:
			raise TypeError("Incorrect value used in Fetch method")

 				
  				
def init_table(app):   #function to create table
	with app.app_context():
		db.create_all()
	return "Table Created"