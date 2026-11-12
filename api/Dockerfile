# Takes the base image for the API docker image
FROM python:3.12.14-alpine3.24

MAINTAINER Kevin Shocosh <kevinshocosh@hotmail.com>

WORKDIR /app

# Update the Alpine package
RUN apk update && apk upgrade --no-cache

# Make a user, because we don't want to run as root
RUN addgroup -S app && adduser -S app -G app

# Install Pythons dependencies
COPY requirements.txt .
COPY converter/ ./converter/

RUN pip install --no-cache-dir -r requirements.txt 
RUN pip install --no-cache-dir ./converter

# Update pip
#RUN pip install --no-cache-dir --upgrade pip 
# Letting this be commented, vuln not fixed yet, will let pip update when fixed.

# Copy application files
COPY src/ ./src/
COPY api/ ./api/

# Prepare for SQL lite data
RUN mkdir -p /data && chown -R app:app /data /app

# Switch to the new user
USER app

CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]
