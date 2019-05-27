from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(name='sonoff-python',
      version='0.1',
      description='Make use of your sonoff smart switches without flashing them via the cloud APIs',
      long_description=long_description,
      long_description_content_type="text/markdown",
      url='https://github.com/lucien2k/sonoff-python',
      author='Alex Cowan',
      author_email='acowan@gmail.com',
      license='MIT',
      classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
      ],
      packages=['sonoff'],
      install_requires=[
        'requests>=2.12.4',
        'websocket-client>=0.54.0'
       ],
      zip_safe=False)
