from setuptools import setup, find_packages

setup(
    name='Pirebase',
    version='3.1.29',
    url='https://github.com/josewails/Pirebase',
    description='A simple python wrapper for the Firebase API',
    author='Joseph Gitonga Wagura',
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.8',
    ],
    keywords='Firebase',
    packages=find_packages(exclude=['tests']),
    install_requires=[
        'requests>=2.20.0',
        'gcloud>=0.18.3',
        'google-auth>=1.22.1',
        'requests_toolbelt>=0.7.0',
        'python_jwt>=2.0.1',
        'pycryptodome>=3.9.8',
        "google-cloud-storage>=1.31.2",
        "sseclient>=0.0.27"
    ]
)
