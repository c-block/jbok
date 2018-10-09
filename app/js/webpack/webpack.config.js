// Load the config generated by scalajs-bundler
const path = require('path');
const config = require('./scalajs.webpack.config');
const CopyWebpackPlugin = require('copy-webpack-plugin');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const merge = require('webpack-merge');

module.exports = merge(config, {
  resolve: {
    alias: {
      "css": path.resolve(__dirname, "../../../../src/main/resources/css"),
    },
    modules: [ path.resolve(__dirname, 'node_modules') ]
  },
  module: {
    rules: [
      {
        test: /\.css$/,
        use: [ 'style-loader', 'css-loader' ]
      }
    ]
  },
  plugins: [
    new HtmlWebpackPlugin({
      inject: false,
      template: path.resolve(__dirname, "../../../../src/main/resources/template.html")
    })
  ]
});
