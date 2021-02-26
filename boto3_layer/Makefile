build-Boto3Layer:
	yum install wget unzip -y
	wget https://s3.amazonaws.com/kabits.com/amazon-lookoutmetrics-python-sdk-2020-12-08.zip
	unzip amazon-lookoutmetrics-python-sdk-2020-12-08.zip -d sdk
	python -m pip install sdk/botocore-1.19.31-py2.py3-none-any.whl -t "$(ARTIFACTS_DIR)/python"
	python -m pip install sdk/boto3-1.16.31-py2.py3-none-any.whl -t "$(ARTIFACTS_DIR)/python"
	python -m pip install -r requirements.txt -t "$(ARTIFACTS_DIR)/python"