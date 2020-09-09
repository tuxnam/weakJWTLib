# pull official base image
FROM python:3.8.1-slim-buster as builder

# set work directory
WORKDIR /usr/src/app

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc

# lint
RUN pip install upgrade pip
RUN pip install flake8
COPY . /usr/src/app
RUN flake8 --ignore=E501,F401

# install dependencies
RUN pip install --upgrade pip
COPY ./requirements.txt .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /usr/src/app/wheels -r requirements.txt

# copy project
COPY . /usr/src/app/

# FINAL #
FROM python:3.8.1-slim-buster

# create directory for the app user
RUN mkdir -p /home/app

# create the app user
RUN addgroup -S app && adduser -S app -G app

# create required dirs
ENV HOME=/home/app
ENV APP_HOME=/home/app/web
RUN mkdir $APP_HOME
WORKDIR $APP_HOME

# Dependencies
RUN apt-get update && apt-get install -y --no-install-recommends netcat
COPY --from=builder /usr/src/app/wheels /wheels
COPY --from=builder /usr/src/app/requirements.txt .
RUN pip install --upgrade pip
RUN pip install --no-cache /wheels/*

# Copy entrypoint
COPY ./entrypoint.sh $APP_HOME

# Copy project
COPY . $APP_HOME

# CHOWN to the app user
RUN chown -R app:app $APP_HOME

# change to app user
USER app

# run
ENTRYPOINT ["/home/app/web/entrypoint.sh"]
