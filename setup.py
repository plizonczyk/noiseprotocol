from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

try:
    import pypandoc
    with open(path.join(here, 'README.md'), encoding='utf-8') as f:
        long_description = pypandoc.convert('README.md', 'rst')
except (IOError, ImportError):
    long_description = 'Check https://github.com/plizonczyk/noiseprotocol for readme.'

setup(
    name='noiseprotocol',
    version='0.3.1',
    description='Implementation of Noise Protocol Framework',
    long_description=long_description,
    url='https://github.com/plizonczyk/noiseprotocol',
    author='Piotr Lizonczyk',
    author_email='plizonczyk.public@gmail.com',
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux'
    ],
    keywords='cryptography noiseprotocol noise security',
    packages=find_packages(exclude=['contrib', 'docs', 'tests', 'examples']),
    install_requires=['cryptography>=2.8'],
    python_requires='~=3.5',  # we like 3.5, 3.6, and beyond, but not 4.0
)
