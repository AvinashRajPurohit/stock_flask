FROM python:3.8
COPY . /docker_stock
WORKDIR /docker_stock
RUN pip install -r requirements.txt
EXPOSE 5001
ENTRYPOINT [ "python" ]
CMD [ "app.py" ]