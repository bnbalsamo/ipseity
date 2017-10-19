from setuptools import setup, find_packages


def readme():
    with open("README.md", 'r') as f:
        return f.read()


setup(
    name="whogoesthere",
    description="An authentication API",
    version="0.0.1",
    long_description=readme(),
    author="Brian Balsamo",
    author_email="brian@brianbalsamo.com",
    packages=find_packages(
        exclude=[
        ]
    ),
    include_package_data=True,
    url='https://github.com/bnbalsamo/whogoesthere',
    dependency_links=[
        'https://github.com/bnbalsamo/flask_jwtlib' +
        '/tarball/master#egg=flask_jwtlib'
    ],
    install_requires=[
        'cryptography',
        'flask>0',
        'flask_env',
        'flask_restful',
        'flask_jwtlib',
        'PyJWT',
        'bcrypt',
        'pymongo'
    ],
    tests_require=[
        'pytest'
    ],
    test_suite='tests'
)
