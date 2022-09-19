FROM python:3.7-slim
LABEL author='v.bars@vidim.ru' version='1.0'

RUN mkdir /app
COPY ./api_yamdb/ /app
RUN pip3 install -r /app/requirements.txt --no-cache-dir
WORKDIR /app
CMD ["gunicorn", "api_yamdb.wsgi:application", "--bind", "0:8000" ]