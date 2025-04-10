import boto3
from dotenv import load_dotenv
import os
from botocore.exceptions import ClientError, ParamValidationError, EndpointConnectionError
from boto3.exceptions import S3UploadFailedError
from helper_functions import validate_env


load_dotenv(".env")

#checks if the eviroment variables are there
variables = ["ACCESS_KEY", "R2_SECRET_KEY", "ACCOUNT_ID", "BUCKET_NAME"]

validate_env(variables)

#class to interact with cloudfare r2
class R2Manager:
	bucket = os.getenv("BUCKET_NAME")
	r2 = boto3.client("s3",
	aws_access_key_id = os.getenv("ACCESS_KEY"),
	aws_secret_access_key = os.getenv("R2_SECRET_KEY"),
	endpoint_url = f"https://s3.eu-central-2.wasabisys.com"
	#https://{os.getenv('ACCOUNT_ID')}.r2.cloudfarestorage.com
	)


	#replace with tus for pausable upload
	def upload(cls, file, stored_filename):
		try:
			cls.r2.upload_fileobj(file, cls.bucket, stored_filename)
		except (EndpointConnectionError, TimeoutError, S3UploadFailedError):
			return False
		return True
		
		
	def preview(cls, filelocation, expiration = 3600):
		try:
			return cls.r2.generate_presigned_url(
			"get_object",
			Params={
				"Bucket": cls.bucket,
				"Key": filelocation,
				"ResponseContentDisposition": "inline"},
			ExpiresIn=expiration)
		except (EndpointConnectionError, TimeoutError, S3UploadFailedError):
			return False
			

	def delete(cls, filelocation):
		try:
			cls.r2.delete_object(Bucket = cls.bucket, Key = filelocation)
			return True
		except (EndpointConnectionError, TimeoutError, S3UploadFailedError):
			return False
	
	
	def get_file(cls, filelocation):
		try:
			file_response = cls.r2.get_object(Bucket = cls.bucket, Key = filelocation)
			return file_response["Body"].read()
		except (EndpointConnectionError, TimeoutError, S3UploadFailedError):
			return False
		except ClientError as e:
			if e.response["Error"]["Code"] == "404":
				return "File not found"