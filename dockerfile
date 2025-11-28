# Python ka lightweight base image use karein (3.11 sabse naya version hai jo stable hai)
FROM python:3.11-slim

# Container ke andar /app directory set karein. /usr/src/app standard hai.
WORKDIR /usr/src/app

# Sabse pehle requirements file copy karein
COPY requirements.txt .

# Python dependencies install karein (gunicorn bhi ismein shamil hona chahiye)
RUN pip install --no-cache-dir -r requirements.txt

# Baaki saari application files copy karein
COPY . .

# Port 8080 expose karein, jahan gunicorn run hoga
EXPOSE 8080 

# FIX: CMD ko Shell Form mein badlein takki /bin/sh gunicorn ko dhoondh sake.
CMD gunicorn --bind 0.0.0.0:8080 CyberX_2:app