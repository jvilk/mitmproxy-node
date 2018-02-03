from setuptools import setup

setup(name='node-mitmproxy',
      version='1.0',
      description='MITMProxy plugin for Node',
      url='http://github.com/jvilk/mitmproxy',
      author='John Vilk',
      author_email='jvilk@cs.umass.edu',
      license='MIT',
      install_requires=[
          'websockets',
      ],
      zip_safe=False)