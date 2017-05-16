from setuptools import setup


setup(name='CoinSwapCS',
      version='0.0.1',
      description='Simple client-server CoinSwap for Bitcoin',
      url='http://github.com/AdamISZ/CoinSwapCS',
      author='Adam Gibson',
      author_email='ekaggata@gmail.com',
      license='GPL',
      packages=['coinswap'],
      install_requires=['twisted==16.6.0', 'joinmarketclient>=0.2.0',
                        'joinmarketbitcoin>=0.2.0', 'pyopenssl', 'txJSON-RPC'],
      zip_safe=False)