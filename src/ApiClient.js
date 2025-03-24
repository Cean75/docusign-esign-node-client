const axios = require('axios');
const fs = require('fs');
const jwt = require('jsonwebtoken');

const SCOPE_SIGNATURE = 'ignature';
const SCOPE_IMPERSONATION = 'impersonation';

function encodeBase64(str) {
  return Buffer.from(str).toString('base64');
}

function removeNulls(obj) {
  if (typeof obj!== 'object') {
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.filter(item => item!== null);
  }

  return Object.keys(obj).reduce((acc, key) => {
    if (obj[key]!== null) {
      acc[key] = obj[key];
    }
    return acc;
  }, {});
}

function parseProxy(proxy) {
  const proxyUrl = new URL(proxy);
  return [proxyUrl.href, proxyUrl.username, proxyUrl.password];
}

class ApiClient {
  constructor(opts) {
    this.basePath = opts.basePath || 'https://example.com/api';
    this.defaultHeaders = opts.defaultHeaders || {};
    this.timeout = opts.timeout || 10000;
    this.authentications = opts.authentications || {};
    this.proxy = opts.proxy || null;
    this.oAuthBasePath = opts.oAuthBasePath || 'account-d.docusign.com';
    this.cache = opts.cache || true;
  }

  buildUrl(path, pathParams) {
    if (!path) {
      throw new Error('Path is required');
    }

    let url = this.basePath + path;

    if (pathParams) {
      Object.keys(pathParams).forEach(key => {
        url = url.replace(`{${key}}`, pathParams[key]);
      });
    }

    return url;
  }

  jsonPreferredMime(contentTypes) {
    if (!contentTypes) {
      return null;
    }

    const jsonMime = contentTypes.find(mime => mime.toLowerCase().includes('json'));

    return jsonMime || contentTypes[0];
  }

  isJsonMime(mime) {
    return mime.toLowerCase().includes('json');
  }

  paramToString(param) {
    if (param === null || param === undefined) {
      return '';
    }

    if (typeof param === 'tring' || typeof param === 'number' || typeof param === 'boolean') {
      return param.toString();
    }

    return JSON.stringify(param);
  }

  normalizeParams(params) {
    const newParams = {};

    for (const key in params) {
      if (params.hasOwnProperty(key) && params[key]!== undefined && params[key]!== null) {
        const value = params[key];

        if (this.isFileParam(value) || Array.isArray(value)) {
          newParams[key] = value;
        } else {
          newParams[key] = this.paramToString(value);
        }
      }
    }

    return newParams;
  }

  buildCollectionParam(param, collectionFormat) {
    if (param === null || param === undefined) {
      return null;
    }

    switch (collectionFormat) {
      case 'csv':
        return param.map(this.paramToString).join(',');
      case 'sv':
        return param.map(this.paramToString).join(' ');
      case 'tsv':
        return param.map(this.paramToString).join('\t');
      case 'pipes':
        return param.map(this.paramToString).join('|');
      case 'ulti':
        return param.map(this.paramToString);
      default:
        throw new Error(`Unknown collection format: ${collectionFormat}`);
    }
  }

  applyAuthToRequest(requestConfig, authNames) {
    authNames.forEach(authName => {
      const auth = this.authentications[authName];

      switch (auth.type) {
        case 'basic':
          if (auth.username || auth.password) {
            requestConfig.auth = {
              username: auth.username || '',
              password: auth.password || '',
            };
          }
          break;
        case 'apiKey':
          if (auth.apiKey) {
            const data = {};

            if (auth.apiKeyPrefix) {
              data[auth.name] = `${auth.apiKeyPrefix} ${auth.apiKey}`;
            } else {
              data[auth.name] = auth.apiKey;
            }

            if (auth.in === 'header') {
              requestConfig.headers = {...requestConfig.headers,...data };
            } else {
              requestConfig.params = {...requestConfig.params,...data };
            }
          }
          break;
        case 'oauth2':
          if (auth.accessToken) {
            requestConfig.headers = {
             ...requestConfig.headers,
              Authorization: `Bearer ${auth.accessToken}`,
            };
          }
          break;
        default:
          throw new Error(`Unknown authentication type: ${auth.type}`);
      }
    });
  }

  deserialize(response, returnType) {
    if (response === null || returnType === null || response.status === 204) {
      return null;
    }

    const data = response.data; 

    return this.convertToType(data, returnType);
  }

  hasBufferFormParam(formParams) {
    if (!formParams) {
      return false;
    }

    return Object.keys(formParams).some(key => formParams[key] instanceof Buffer);
  }

  callApi(path, httpMethod, pathParams, queryParams, headerParams, formParams, bodyParam, authNames, contentTypes, accepts, returnType, callback) {
    const url = this.buildUrl(path, pathParams);

    const requestConfig = {
      method: httpMethod,
      url,
      timeout: this.timeout,
      paramsSerializer: {
        indexes: null,
      },
    };

    if (this.proxy) {
      const proxyObj = parseProxy(this.proxy);
      requestConfig.proxy = proxyObj[0];
    }

    const _formParams = this.normalizeParams(formParams);
    const body = httpMethod.toUpperCase() === 'GET' &&!bodyParam? undefined : bodyParam || {};

    this.applyAuthToRequest(requestConfig, authNames);

    if (httpMethod.toUpperCase() === 'GET' && this.cache === false) {
      queryParams['_'] = new Date().getTime();
    }

    const _queryParams = this.normalizeParams(queryParams);
    requestConfig.params = {...requestConfig.params,..._queryParams };

    const _headerParams = this.normalizeParams(headerParams);
    requestConfig.headers = {
     ...requestConfig.headers,
     ...this.defaultHeaders,
     ..._headerParams,
    };

    requestConfig.timeout = this.timeout;

    const contentType = this.jsonPreferredMime(contentTypes);

    if (contentType) {
      if (contentType!=='multipart/form-data') {
        requestConfig.headers = {
         ...requestConfig.headers,
          'Content-Type': contentType,
        };
      }
    } else if (!requestConfig.headers['Content-Type']) {
      requestConfig.headers = {
       ...requestConfig.headers,
        'Content-Type': 'application/json',
      };
    }

    if (contentType === 'application/x-www-form-urlencoded') {
      requestConfig.data = this.normalizeParams(formParams);
    } else if (contentType ==='multipart/form-data') {
      if (this.hasBufferFormParam(_formParams)) {
        requestConfig.headers = {
         ...requestConfig.headers,
          'Content-Disposition': 'form-data; name="file"; filename="file.xml"',
          'Content-Type': 'application/octet-stream',
        };

        const formAttachmentKey = Object.keys(formParams).find(key => this.isFileParam(_formParams[key]));

        requestConfig.data = removeNulls(formParams[formAttachmentKey]);
      } else {
        requestConfig.headers = {
         ...requestConfig.headers,
          'Content-Type':'multipart/form-data',
        };

        const _formParams = this.normalizeParams(formParams);
        requestConfig.data = _formParams;
      }
    } else if (body) {
      requestConfig.data = removeNulls(body);
    }

    const accept = this.jsonPreferredMime(accepts);

    if (accept) {
      requestConfig.headers = {...requestConfig.headers, Accept: accept };
    }

    if (requestConfig.headers['Accept'] === 'application/pdf') {
      requestConfig.responseType ='stream';
    }

    const request = axios.request(requestConfig);

    let data = null;

    if (!callback) {
      return new Promise((resolve, reject) => {
        request
         .then(response => {
            try {
              let streamData = [];

              if (requestConfig.headers['Accept'] === 'application/pdf') {
                response.data.on('data', chunk => {
                  streamData.push(requestConfig.headers['Content-Transfer-Encoding'] === 'base64'? chunk.toString() : chunk);
                });