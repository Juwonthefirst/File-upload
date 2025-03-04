import boto3
from dotenv import load_dotenv
import os
from botocore.exceptions import ClientError

load_dotenv(".env")

#checks if the eviroment variables are there
variables = ["ACCESS_KEY", "R2_SECRET_KEY", "ACCOUNT_ID", "BUCKET_NAME"]
for var in variables:
	if not os.getenv(var):
		raise RuntimeError(f"{var} is not set, check your enviroment variable")

#class to interact with cloudfare r2
class R2:
	bucket = os.getenv("BUCKET_NAME")
	r2 = boto3.client("s3",
	aws_access_key_id = os.getenv("ACCESS_KEY"),
	aws_secret_access_key = os.getenv("R2_SECRET_KEY"),
	endpoint_url = f"https://{os.getenv('ACCOUNT_ID')}.r2.cloudfarestorage.com"
	)


	@classmethod
	def upload(cls, file, stored_filename):
		try:
			cls.r2.upload_fileobj(file, cls.bucket, stored_filename)
		except ClientError:
			return False
		return True
		
		
	@classmethod
	def download(cls, stored_filename, expiration):
		try:
			return cls.r2.generate_presigned_url(
			"get_object",
			Params={
				"Bucket": cls.bucket,
				"Key": stored_filename,
				"ResponseContentDisposition": "attachment"},
			ExpiresIn=expiration)
		except ClientError:
			return False
			
	@classmethod
	def delete(cls):
		pass
	