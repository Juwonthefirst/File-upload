from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, String, DateTime, Text, ForeignKey, Update, and_, or_
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func
from sqlalchemy.exc import IntegrityError
from datetime import datetime
from typing import List

db = SQLAlchemy()


# class for User table that stores user data
class Users(db.Model):
	
	id: Mapped[int] = mapped_column(Integer, primary_key = True)
	firstname: Mapped[str] = mapped_column(String(60), nullable = False)
	lastname: Mapped[str] = mapped_column(String(60), nullable = False)
	username: Mapped[str] = mapped_column(String(20), unique = True, nullable = False)
	email: Mapped[str] = mapped_column(String(255), unique = True, nullable = False)
	password: Mapped[str] = mapped_column(String(255), nullable = False)
	created_at: Mapped[datetime] = mapped_column(DateTime, server_default = func.now())
	uploads:Mapped[List["Uploads"]] = relationship("Uploads", backref="uploader", lazy = "dynamic", cascade = "all, delete-orphan")
	
	
	def __repr__(self):
		return f"Users({self.username}, {self.email}, {self.created_at})"
	
	def save(self):
		try:
			db.session.add(self)
			db.session.commit()
			return f"{self.username} successfully added to database"
		except IntegrityError:
			return False	
			
	def delete(self):
		db.session.delete(self)
		db.session.commit()
		return f"{self.username} successfully deleted from database"
		
	@classmethod
	def update_firstname(cls, user_id, new_name):
		user = db.session.get(cls, user_id)
		user.firstname = new_name
		db.session.commit()
		return "First name change successful"
		
	@classmethod
	def update_lastname(cls, user_id, new_name):
		user = db.session.get(cls, user_id)
		user.lastname = new_name
		db.session.commit()
		return "Last name change successful"
		
	
	@classmethod
	def update_email(cls, user_id, new_email):
		user = db.session.get(cls, user_id)
		user.email = new_email
		db.session.commit()
		return "Email change successful"
		
		
	@classmethod
	def update_pass(cls,user_id, new_pass):
		user = db.session.get(cls, user_id)
		user.password = new_pass
		db.session.commit()
		return " password updated"
		
		
	# to fetch user details from the database			
	@classmethod		
	def fetch(cls, area, user_detail, search = None):
		if area in ["password", "username", "email"] and search in ["password", "username", "email", None]:
			if not search:
				search = area
			return db.session.execute( db.select(getattr(cls, area)).where(getattr(cls, search) == user_detail)).scalar_one_or_none()
		else:
			raise TypeError("Incorrect value used in Fetch method")	
			
	@classmethod
	def fetch_user_row(cls, detail):
		return db.session.execute(db.select(cls).where(or_(cls.username == detail, cls.email == detail))).scalar_one_or_none()
			

#class for table to store all uploads made by users
																
class Uploads(db.Model):
	
	id:Mapped[int] = mapped_column(Integer, primary_key = True)
	filename: Mapped[str] = mapped_column(String(255), nullable = False)
	filesize:Mapped[int] = mapped_column(Integer, nullable = False)
	folder:Mapped[str] = mapped_column(String(50), nullable = False)
	filelocation:Mapped[str] = mapped_column(String(255), unique = True) 
	content_type:Mapped[str] = mapped_column(String(255), nullable=False)
	uploaded_at: Mapped[datetime] = mapped_column(DateTime, server_default = func.now())
	user_id: Mapped[int] = mapped_column(db.ForeignKey("users.id"), nullable = False)
	
	__table_args__ = (
	db.UniqueConstraint("folder", "filename","user_id", name = "unique_file_in_folder"),
)
	
	def __repr__(self):
		return f"File({self.filename}, {self.filesize})"
		
	def save(self):
		try:
			db.session.add(self)
			db.session.commit()
			return f"{self.filename} uploaded successfully"
		except IntegrityError:
			return False
		
	def delete(self):
		db.session.delete(self)
		db.session.commit()
		return f"{self.filename} deleted successfully"
		
	@classmethod
	def update_name(cls, user_id, new_filename):
		upload = db.session.get(cls, user_id)
		upload.filename = new_filename
		db.session.commit()
		return f"{upload.filename} password updated"
		
		
	# to fetch user uploads details from the database			
	@classmethod		
	def fetch(cls, area, user_detail, search = None, all = False):
		if area in ["filename", "folder", "user_id", "filesize"] and search in ["filename", "folder", "user_id", None]:
			if not search:
				search = area
			data = db.session.execute( db.select(getattr(cls, area)).order_by(getattr(cls, area)).where(getattr(cls, search) == user_detail))
			
			if all:
				return data.scalars().all()
			return data.scalar_one_or_none()
			
		else:
			raise TypeError("Incorrect value used in Fetch method")


	@classmethod
	def fetch_filerow(cls, user_id, folder, filename):
		return db.session.execute(
		db.select(cls).where(
			and_(
					cls.folder == folder, 
					cls.filename == filename,
					cls.user_id == user_id
					)
				) 
			).scalar_one_or_none()
			
	@classmethod
	def fetch_filename(cls, user_id, folder, all = False):
		raw_files = db.session.execute(
			db.select(cls.filename).where(
				and_(
						cls.folder == folder, 
						cls.user_id == user_id
					)
				) 
			)
		if all:
			return raw_files.scalars().all()
		return raw_files.scalar_one_or_none()
		
 
 #table class for storing error logs				
class Errors(db.Model):
	id: Mapped[int] = mapped_column(Integer, primary_key = True)
	error: Mapped[str] = mapped_column(String(255), nullable = False)
	time: Mapped[datetime] = mapped_column(DateTime, server_default = func.now())
	user_id: Mapped[int] = mapped_column(db.ForeignKey("users.id"), nullable = True)
	
	
	def __repr__(self):
		return f"{error} for user {user_id} during {time}"
	
	def log(self):
		db.session.add(self)
		db.session.commit()
		return "Error logged"
 		
 		
 #function to create table if they don't exist 				
def init_table(app):   
	with app.app_context():
		db.create_all()
	return "Table Created"