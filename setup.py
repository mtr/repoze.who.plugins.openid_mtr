from setuptools import setup, find_packages
import os

version = '0.5.2'

setup(name='repoze.who.plugins.openid',
      version=version,
      description="An OpenID plugin for repoze.who",
      long_description=open("README.txt").read() + "\n" +
                       open(os.path.join("docs", "HISTORY.txt")).read(),
      # Get more strings from http://www.python.org/pypi?%3Aaction=list_classifiers
      classifiers=[
        "Programming Language :: Python",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware",
        ],
      keywords='openid repoze who identification authentication plugin',
      author='Christian Scholz',
      author_email='cs@comlounge.net',
      url='http://quantumcore.org/docs/repoze.who.plugins.openid',
      license="BSD-derived (http://www.repoze.org/LICENSE.txt)",
      packages=find_packages(exclude=['ez_setup']),
      namespace_packages=['repoze', 'repoze.who', 'repoze.who.plugins'],
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          'repoze.who>=1.0.6', 
	  'python-openid>=2.0',
          'setuptools',
          'webob',
          'zope.interface'
      ],
      test_requires=[   
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      test_suite='repoze.who.plugins.openid.tests'
      )
