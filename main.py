from flask import Flask, request, render_template, redirect, url_for, flash, session


app=Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///mock.db"
app.config["SECRET_KEY"] = "c0013adc9440afb24b0e40c0e0d3274c"
