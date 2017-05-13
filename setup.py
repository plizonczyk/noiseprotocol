from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='noise-python',
    version='0.1.0',
    description='A sample Python project',  # TODO
    long_description=long_description,
    url='https://github.com/plizonczyk/',
    author='Piotr Lizonczyk',
    author_email='piotr.lizonczyk@gmail.com',
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    keywords='',  # TODO
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),
    install_requires=[],  # TODO
)
