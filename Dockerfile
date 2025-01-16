FROM python:3.12.5-alpine
ENV PYTHONUNBUFFERED 1

RUN mkdir "/app"
WORKDIR "/app"

COPY requirements.txt /App/

RUN pip install  -r requirements.txt

EXPOSE 8000

ADD AuthApp /App/
