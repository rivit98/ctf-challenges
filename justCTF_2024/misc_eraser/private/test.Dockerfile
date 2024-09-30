FROM python:3.12

RUN pip install parameterized

COPY test.py eraser /app/

