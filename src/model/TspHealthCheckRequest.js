/**
 * DocuSign REST API
 * The DocuSign REST API provides you with a powerful, convenient, and simple Web services API for interacting with DocuSign.
 *
 * OpenAPI spec version: v2.1
 * Contact: devcenter@docusign.com
 *
 * NOTE: This class is auto generated. Do not edit the class manually and submit a new issue instead.
 *
 */

(function(root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['ApiClient', 'model/TspHealthCheckStatusDescription'], factory);
  } else if (typeof module === 'object' && module.exports) {
    // CommonJS-like environments that support module.exports, like Node.
    module.exports = factory(require('../ApiClient'), require('./TspHealthCheckStatusDescription'));
  } else {
    // Browser globals (root is window)
    if (!root.Docusign) {
      root.Docusign = {};
    }
    root.Docusign.TspHealthCheckRequest = factory(root.Docusign.ApiClient, root.Docusign.TspHealthCheckStatusDescription);
  }
}(this, function(ApiClient, TspHealthCheckStatusDescription) {
  'use strict';


  /**
   * The TspHealthCheckRequest model module.
   * @module model/TspHealthCheckRequest
   * @version 5.3.0
   */

  /**
   * Constructs a new <code>TspHealthCheckRequest</code>.
   * @alias module:model/TspHealthCheckRequest
   * @class
   */
  var exports = function() {
    var _this = this;


  };

  /**
   * Constructs a <code>TspHealthCheckRequest</code> from a plain JavaScript object, optionally creating a new instance.
   * Copies all relevant properties from <code>data</code> to <code>obj</code> if supplied or a new instance if not.
   * @param {Object} data The plain JavaScript object bearing properties of interest.
   * @param {module:model/TspHealthCheckRequest} obj Optional instance to populate.
   * @return {module:model/TspHealthCheckRequest} The populated <code>TspHealthCheckRequest</code> instance.
   */
  exports.constructFromObject = function(data, obj) {
    if (data) {
      obj = obj || new exports();

      if (data.hasOwnProperty('appVersion')) {
        obj['appVersion'] = ApiClient.convertToType(data['appVersion'], 'String');
      }
      if (data.hasOwnProperty('description')) {
        obj['description'] = ApiClient.convertToType(data['description'], 'String');
      }
      if (data.hasOwnProperty('error')) {
        obj['error'] = ApiClient.convertToType(data['error'], 'String');
      }
      if (data.hasOwnProperty('status')) {
        obj['status'] = ApiClient.convertToType(data['status'], 'String');
      }
      if (data.hasOwnProperty('statusDescription')) {
        obj['statusDescription'] = ApiClient.convertToType(data['statusDescription'], [TspHealthCheckStatusDescription]);
      }
    }
    return obj;
  }

  /**
   * 
   * @member {String} appVersion
   */
  exports.prototype['appVersion'] = undefined;
  /**
   * 
   * @member {String} description
   */
  exports.prototype['description'] = undefined;
  /**
   * 
   * @member {String} error
   */
  exports.prototype['error'] = undefined;
  /**
   * Indicates the envelope status. Valid values are:  * sent - The envelope is sent to the recipients.  * created - The envelope is saved as a draft and can be modified and sent later.
   * @member {String} status
   */
  exports.prototype['status'] = undefined;
  /**
   * 
   * @member {Array.<module:model/TspHealthCheckStatusDescription>} statusDescription
   */
  exports.prototype['statusDescription'] = undefined;



  return exports;
}));


