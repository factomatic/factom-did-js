const path = require('path');

module.exports = {
  mode: 'production',
  entry: {
    'factom-did': './src/factom-did.js'
  }, 
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: '[name].js',
    library: '[name]',
    libraryTarget: 'umd',
  },
  module: {
    rules: [
      {
        test: /\.(js)$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
              presets: ['@babel/env'],
              plugins: ['@babel/transform-runtime', '@babel/transform-async-to-generator',  '@babel/transform-modules-commonjs']
          }
        }
      },
    ],
  }
};
