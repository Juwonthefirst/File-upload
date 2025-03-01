from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func
from datetime import datetime
from typing import List

db = SQLAlchemy()


# class for User table that stores user data
class Users(db.Model):
	
	id: Mapped[int] = mapped_column(Integer, primary_key = True)
	username: Mapped[str] = mapped_column(String, unique = True, nullable = False)
	email: Mapped[str] = mapped_column(String, unique = True, nullable = False)
	password: Mapped[str] = mapped_column(String, nullable = False)
	created_at: Mapped[datetime] = mapped_column(DateTime, server_default = func.now())
	links:Mapped[List["Links"]] = relationship("Links", back_populates = "uploads")
	
	
	def __repr__(self):
		return f"{self.username} successfully added to database"
		
	def add(self):
		db.session.add(self)
		db.session.commit()
		
	def delete(self):
		db.session.delete(self)
		db.session.commit()
		
		
def Fetch_user(area, user_detail, search = None):
	if area in ["pass", "username", "email"]:
				if not search:
					search = area
				return db.session.execute(db.select(area).Where(search == user_detail)).scalar_one()
	else:
		raise TypeError("Incorrect value used in Fetch_user")
				
								
												
																				
				
class Links(db.Model):
	
	id:Mapped[int] = mapped_column(Integer, primary_key = True)
	filename: Mapped[str] = mapped_column(String, nullable = False)
	filelink: Mapped[str] = mapped_column(String, nullable = False, unique = True)
	user: Mapped["str"] = mapped_column(db.ForeignKey("users.username"), nullable = False)
	
 				
def create_table():
	with app.app_context():
		db.create_all()
	return "Table Created"