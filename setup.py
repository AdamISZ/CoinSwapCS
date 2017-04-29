from setuptools import setup


setup(name='CoinSwapCS',
      version='0.1',
      description='Simple client-server CoinSwap for Bitcoin',
      url='http://github.com/AdamISZ/CoinSwapCS',
      author='Adam Gibson',
      author_email='ekaggata@gmail.com',
      license='GPL',
      packages=['coinswapcs'],
      install_requires=['twisted==16.6.0', 'joinmarketclient',
                        'joinmarketbitcoin', 'pyopenssl', 'txJSON-RPC', 'pytest'],
      zip_safe=False)
