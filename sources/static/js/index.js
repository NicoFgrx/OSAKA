(function webpackUniversalModuleDefinition(root, factory) {
	if(typeof exports === 'object' && typeof module === 'object')
		module.exports = factory();
	else if(typeof define === 'function' && define.amd)
		define([], factory);
	else {
		var a = factory();
		for(var i in a) (typeof exports === 'object' ? exports : root)[i] = a[i];
	}
})(this, function() {
return /******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};
/******/
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/
/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId]) {
/******/ 			return installedModules[moduleId].exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			i: moduleId,
/******/ 			l: false,
/******/ 			exports: {}
/******/ 		};
/******/
/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/
/******/ 		// Flag the module as loaded
/******/ 		module.l = true;
/******/
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/
/******/
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;
/******/
/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;
/******/
/******/ 	// define getter function for harmony exports
/******/ 	__webpack_require__.d = function(exports, name, getter) {
/******/ 		if(!__webpack_require__.o(exports, name)) {
/******/ 			Object.defineProperty(exports, name, { enumerable: true, get: getter });
/******/ 		}
/******/ 	};
/******/
/******/ 	// define __esModule on exports
/******/ 	__webpack_require__.r = function(exports) {
/******/ 		if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 			Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 		}
/******/ 		Object.defineProperty(exports, '__esModule', { value: true });
/******/ 	};
/******/
/******/ 	// create a fake namespace object
/******/ 	// mode & 1: value is a module id, require it
/******/ 	// mode & 2: merge all properties of value into the ns
/******/ 	// mode & 4: return value when already ns object
/******/ 	// mode & 8|1: behave like require
/******/ 	__webpack_require__.t = function(value, mode) {
/******/ 		if(mode & 1) value = __webpack_require__(value);
/******/ 		if(mode & 8) return value;
/******/ 		if((mode & 4) && typeof value === 'object' && value && value.__esModule) return value;
/******/ 		var ns = Object.create(null);
/******/ 		__webpack_require__.r(ns);
/******/ 		Object.defineProperty(ns, 'default', { enumerable: true, value: value });
/******/ 		if(mode & 2 && typeof value != 'string') for(var key in value) __webpack_require__.d(ns, key, function(key) { return value[key]; }.bind(null, key));
/******/ 		return ns;
/******/ 	};
/******/
/******/ 	// getDefaultExport function for compatibility with non-harmony modules
/******/ 	__webpack_require__.n = function(module) {
/******/ 		var getter = module && module.__esModule ?
/******/ 			function getDefault() { return module['default']; } :
/******/ 			function getModuleExports() { return module; };
/******/ 		__webpack_require__.d(getter, 'a', getter);
/******/ 		return getter;
/******/ 	};
/******/
/******/ 	// Object.prototype.hasOwnProperty.call
/******/ 	__webpack_require__.o = function(object, property) { return Object.prototype.hasOwnProperty.call(object, property); };
/******/
/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "";
/******/
/******/
/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(__webpack_require__.s = "./projects/icons/src/index.ts");
/******/ })
/************************************************************************/
/******/ ({

/***/ "./projects/icons/src/clr-icons-api.ts":
/*!*********************************************!*\
  !*** ./projects/icons/src/clr-icons-api.ts ***!
  \*********************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

/*
 * Copyright (c) 2016-2021 VMware, Inc. All Rights Reserved.
 * This software is released under MIT license.
 * The full license information can be found in LICENSE in the root directory of this project.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.ClarityIconsApi = void 0;
var shape_template_observer_1 = __webpack_require__(/*! ./utils/shape-template-observer */ "./projects/icons/src/utils/shape-template-observer.ts");
var iconShapeSources = {};
var ClarityIconsApi = /** @class */ (function () {
    function ClarityIconsApi() {
    }
    Object.defineProperty(ClarityIconsApi, "instance", {
        get: function () {
            if (!ClarityIconsApi.singleInstance) {
                ClarityIconsApi.singleInstance = new ClarityIconsApi();
            }
            return ClarityIconsApi.singleInstance;
        },
        enumerable: false,
        configurable: true
    });
    ClarityIconsApi.prototype.validateName = function (name) {
        if (name.length === 0) {
            throw new Error('Shape name or alias must be a non-empty string!');
        }
        if (/\s/.test(name)) {
            throw new Error('Shape name or alias must not contain any whitespace characters!');
        }
        return true;
    };
    ClarityIconsApi.prototype.normalizeShapeName = function (shapeName) {
        return shapeName.toLowerCase();
    };
    ClarityIconsApi.prototype.setIconTemplate = function (shapeName, shapeTemplate) {
        var trimmedShapeTemplate = shapeTemplate.trim();
        if (this.validateName(shapeName)) {
            // Make sure the shapeName don't contain uppercase characters
            // when registering it
            shapeName = this.normalizeShapeName(shapeName);
            // if the shape name exists, delete it.
            if (iconShapeSources[shapeName]) {
                delete iconShapeSources[shapeName];
            }
            iconShapeSources[shapeName] = trimmedShapeTemplate;
            shape_template_observer_1.ShapeTemplateObserver.instance.emitChanges(shapeName, trimmedShapeTemplate);
        }
    };
    ClarityIconsApi.prototype.setIconAliases = function (templates, shapeName, aliasNames) {
        for (var _i = 0, aliasNames_1 = aliasNames; _i < aliasNames_1.length; _i++) {
            var aliasName = aliasNames_1[_i];
            if (this.validateName(aliasName)) {
                Object.defineProperty(templates, aliasName, {
                    get: function () {
                        return templates[shapeName];
                    },
                    enumerable: true,
                    configurable: true,
                });
            }
        }
    };
    ClarityIconsApi.prototype.add = function (icons) {
        if (typeof icons !== 'object') {
            throw new Error("The argument must be an object literal passed in the following pattern:\n                { \"shape-name\": \"shape-template\" }");
        }
        for (var shapeName in icons) {
            if (icons.hasOwnProperty(shapeName)) {
                this.setIconTemplate(shapeName, icons[shapeName]);
            }
        }
    };
    ClarityIconsApi.prototype.has = function (shapeName) {
        return !!iconShapeSources[this.normalizeShapeName(shapeName)];
    };
    ClarityIconsApi.prototype.get = function (shapeName) {
        // if shapeName is not given, return all icon templates.
        if (!shapeName) {
            return iconShapeSources;
        }
        if (typeof shapeName !== 'string') {
            throw new TypeError('Only string argument is allowed in this method.');
        }
        return iconShapeSources[this.normalizeShapeName(shapeName)];
    };
    ClarityIconsApi.prototype.alias = function (aliases) {
        if (typeof aliases !== 'object') {
            throw new Error("The argument must be an object literal passed in the following pattern:\n                { \"shape-name\": [\"alias-name\", ...] }");
        }
        for (var shapeName in aliases) {
            if (aliases.hasOwnProperty(shapeName)) {
                if (iconShapeSources.hasOwnProperty(shapeName)) {
                    // set an alias to the icon if it exists in iconShapeSources.
                    this.setIconAliases(iconShapeSources, shapeName, aliases[shapeName]);
                }
                else {
                    throw new Error("An icon \"" + shapeName + "\" you are trying to set aliases to doesn't exist in the Clarity Icons sets!");
                }
            }
        }
    };
    return ClarityIconsApi;
}());
exports.ClarityIconsApi = ClarityIconsApi;


/***/ }),

/***/ "./projects/icons/src/clr-icons-element.ts":
/*!*************************************************!*\
  !*** ./projects/icons/src/clr-icons-element.ts ***!
  \*************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
exports.ClarityIconElement = void 0;
/*
 * Copyright (c) 2016-2021 VMware, Inc. All Rights Reserved.
 * This software is released under MIT license.
 * The full license information can be found in LICENSE in the root directory of this project.
 */
var clr_icons_api_1 = __webpack_require__(/*! ./clr-icons-api */ "./projects/icons/src/clr-icons-api.ts");
var shape_template_observer_1 = __webpack_require__(/*! ./utils/shape-template-observer */ "./projects/icons/src/utils/shape-template-observer.ts");
/* CLR-ICON CUSTOM ELEMENT */
var clrIconId = 0;
var offScreenSpan = document.createElement('span');
offScreenSpan.className = 'is-off-screen';
var parentConstructor = function () {
    // eslint-disable-next-line prefer-rest-params
    return HTMLElement.apply(this, arguments);
};
if (typeof Reflect === 'object') {
    parentConstructor = function () {
        // eslint-disable-next-line prefer-rest-params
        return Reflect.construct(HTMLElement, arguments, this.constructor);
    };
}
function ClarityIconElement() {
    'use strict';
    // eslint-disable-next-line prefer-rest-params
    var _instance = parentConstructor.apply(this, arguments);
    _instance.clrIconUniqId = '_clr_icon_' + clrIconId;
    clrIconId++;
    return _instance;
}
exports.ClarityIconElement = ClarityIconElement;
ClarityIconElement.observedAttributes = ['shape', 'size', 'title'];
ClarityIconElement.prototype = Object.create(HTMLElement.prototype, {
    constructor: { configurable: true, writable: true, value: ClarityIconElement },
});
ClarityIconElement.prototype.constructor = ClarityIconElement;
ClarityIconElement.prototype._appendCustomTitle = function () {
    var cloneOffScreenSpan = offScreenSpan.cloneNode(false);
    cloneOffScreenSpan.id = this.clrIconUniqId;
    cloneOffScreenSpan.textContent = this.currentTitleAttrVal;
    this.appendChild(cloneOffScreenSpan);
};
ClarityIconElement.prototype._setIconSize = function (size) {
    if (!Number(size) || Number(size) < 0) {
        this.style.width = null; // fallback to the original stylesheet value
        this.style.height = null; // fallback to the original stylesheet value
    }
    else {
        this.style.width = size + 'px';
        this.style.height = size + 'px';
    }
};
ClarityIconElement.prototype._normalizeShape = function (value) {
    return value.split(/\s/)[0].toLowerCase();
};
ClarityIconElement.prototype.connectedCallback = function () {
    // One thing to note here is that the attributeChangedCallback method is called for every attribute first
    // before this connectedCallback method called only once when the custom element is inserted into the DOM.
    // So we could check whether the attribute values really changed or not.
    // If not, we don't need to execute the same codes again.
    var _this = this;
    // We want to hide the custom element from screen readers but allow the svg/img content to still be read inline
    // Adding role=none allows the screen reader to skip the custom element as if it were a div or span.
    // https://www.scottohara.me/blog/2018/05/05/hidden-vs-none.html
    if (!this.getAttribute('role')) {
        this.setAttribute('role', 'none');
    }
    if (this.hasAttribute('size')) {
        var sizeAttrValue = this.getAttribute('size');
        if (this.currentSizeAttrVal !== sizeAttrValue) {
            this.currentSizeAttrVal = sizeAttrValue;
            this._setIconSize(sizeAttrValue);
        }
    }
    // Note: the size attribute is irrelevant from the shape template;
    // That's why the size checking placed before detecting changes in shape and title attributes.
    // This means even if the shape is not found, the injected shape will have the user-given size.
    if (this.hasAttribute('shape')) {
        var shapeAttrValue = this._normalizeShape(this.getAttribute('shape'));
        this._shapeTemplateSubscription = shape_template_observer_1.ShapeTemplateObserver.instance.subscribeTo(shapeAttrValue, function (updatedTemplate) {
            _this._injectTemplate(updatedTemplate);
        });
        this.currentShapeAttrVal = shapeAttrValue;
        if (clr_icons_api_1.ClarityIconsApi.instance.has(this.currentShapeAttrVal)) {
            var currentShapeTemplate = clr_icons_api_1.ClarityIconsApi.instance.get(this.currentShapeAttrVal);
            if (currentShapeTemplate === this.currentShapeTemplate) {
                return;
            }
            else {
                this.currentShapeTemplate = currentShapeTemplate;
            }
        }
        else {
            this._injectErrorTemplate();
            return;
        }
    }
    if (this.hasAttribute('title')) {
        var titleAttrValue = this.getAttribute('title');
        if (this.currentTitleAttrVal !== titleAttrValue) {
            this.currentTitleAttrVal = titleAttrValue;
        }
        if (!this.currentShapeAttrVal) {
            return;
        }
    }
    this._injectTemplate();
};
ClarityIconElement.prototype.attributeChangedCallback = function (attributeName, _oldValue, newValue) {
    var _this = this;
    if (attributeName === 'size') {
        this._setIconSize(newValue);
    }
    // Note: the size attribute is irrelevant from the shape template;
    // That's why the size checking placed before detecting changes in shape and title attributes.
    // This means even if the shape is not found, the injected shape will have the user-given size.
    if (attributeName === 'shape') {
        this.currentShapeAttrVal = this._normalizeShape(newValue);
        // transfer change handler callback to new shape name
        if (this._shapeTemplateSubscription) {
            // remove the existing change handler callback on the old shape name
            this._shapeTemplateSubscription();
            // create a new subscription on the new shape name
            this._shapeTemplateSubscription = shape_template_observer_1.ShapeTemplateObserver.instance.subscribeTo(this.currentShapeAttrVal, function (updatedTemplate) {
                _this._injectTemplate(updatedTemplate);
            });
        }
        if (clr_icons_api_1.ClarityIconsApi.instance.has(this.currentShapeAttrVal)) {
            this.currentShapeTemplate = clr_icons_api_1.ClarityIconsApi.instance.get(this.currentShapeAttrVal);
        }
        else {
            this._injectErrorTemplate();
            return;
        }
    }
    if (attributeName === 'title') {
        this.currentTitleAttrVal = newValue;
        if (!this.currentShapeAttrVal) {
            return;
        }
    }
    this._injectTemplate();
};
ClarityIconElement.prototype.disconnectedCallback = function () {
    // as the icon element is removed from the DOM,
    // remove its listener callback function as well.
    if (this._shapeTemplateSubscription) {
        this._shapeTemplateSubscription();
    }
};
ClarityIconElement.prototype._setAriaLabelledBy = function () {
    var existingAriaLabelledBy = this.getAttribute('aria-labelledby');
    var svgElement = this.querySelector('svg');
    var elementToSet = svgElement ? svgElement : this;
    if (!existingAriaLabelledBy) {
        elementToSet.setAttribute('aria-labelledby', this.clrIconUniqId);
    }
    else if (existingAriaLabelledBy && existingAriaLabelledBy.indexOf(this.clrIconUniqId) < 0) {
        elementToSet.setAttribute('aria-labelledby', existingAriaLabelledBy + ' ' + this.clrIconUniqId);
    }
};
ClarityIconElement.prototype._injectTemplate = function (shapeTemplate) {
    // Accepting the argument, shapeTemplate, will help us to update the shape template
    // right before the injection.
    if (shapeTemplate && shapeTemplate !== this.currentShapeTemplate) {
        this.currentShapeTemplate = shapeTemplate;
    }
    this.innerHTML = this.currentShapeTemplate;
    if (this.currentTitleAttrVal) {
        this._setAriaLabelledBy();
        this._appendCustomTitle();
    }
};
ClarityIconElement.prototype._injectErrorTemplate = function () {
    this.currentShapeTemplate = clr_icons_api_1.ClarityIconsApi.instance.get('error');
    this._injectTemplate();
};


/***/ }),

/***/ "./projects/icons/src/index.ts":
/*!*************************************!*\
  !*** ./projects/icons/src/index.ts ***!
  \*************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
exports.ClarityIcons = void 0;
/*
 * Copyright (c) 2016-2021 VMware, Inc. All Rights Reserved.
 * This software is released under MIT license.
 * The full license information can be found in LICENSE in the root directory of this project.
 */
var clr_icons_api_1 = __webpack_require__(/*! ./clr-icons-api */ "./projects/icons/src/clr-icons-api.ts");
var clr_icons_element_1 = __webpack_require__(/*! ./clr-icons-element */ "./projects/icons/src/clr-icons-element.ts");
var core_shapes_1 = __webpack_require__(/*! ./shapes/core-shapes */ "./projects/icons/src/shapes/core-shapes.ts");
var clarityIcons = clr_icons_api_1.ClarityIconsApi.instance;
exports.ClarityIcons = clarityIcons;
clarityIcons.add(core_shapes_1.CoreShapes);
// check if there is a global object called "ClarityIcons"
if (typeof window !== 'undefined') {
    if (!window.hasOwnProperty('ClarityIcons')) {
        // Setting a global object called "ClarityIcons" to expose the ClarityIconsApi.
        window.ClarityIcons = clarityIcons;
    }
    // Defining clr-icon custom element
    if (!customElements.get('clr-icon')) {
        customElements.define('clr-icon', clr_icons_element_1.ClarityIconElement);
    }
}


/***/ }),

/***/ "./projects/icons/src/shapes/core-shapes.ts":
/*!**************************************************!*\
  !*** ./projects/icons/src/shapes/core-shapes.ts ***!
  \**************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
exports.CoreShapes = exports.ClrShapeArrow = exports.ClrShapeStepForward2 = exports.ClrShapeEyeHide = exports.ClrShapeEye = exports.ClrShapeEvent = exports.ClrShapeCalendar = exports.ClrShapeAngleDouble = exports.ClrShapeViewColumns = exports.ClrShapeSearch = exports.ClrShapeVmBug = exports.ClrShapeFilterGridCircle = exports.ClrShapeFilterGrid = exports.ClrShapeEllipsisVertical = exports.ClrShapeEllipsisHorizontal = exports.ClrShapeCloud = exports.ClrShapeImage = exports.ClrShapeBell = exports.ClrShapeFolderOpen = exports.ClrShapeFolder = exports.ClrShapeAngle = exports.ClrShapeUser = exports.ClrShapeBars = exports.ClrShapeHelpInfo = exports.ClrShapeWarningStandard = exports.ClrShapeErrorStandard = exports.ClrShapeSuccessStandard = exports.ClrShapeInfoStandard = exports.ClrShapeInfoCircle = exports.ClrShapeCheckCircle = exports.ClrShapeExclamationCircle = exports.ClrShapeExclamationTriangle = exports.ClrShapeTimes = exports.ClrShapeCheck = exports.ClrShapeCog = exports.ClrShapeHome = exports.ClrShapeUnknownStatus = void 0;
/*
 * Copyright (c) 2016-2021 VMware, Inc. All Rights Reserved.
 * This software is released under MIT license.
 * The full license information can be found in LICENSE in the root directory of this project.
 */
var descriptor_config_1 = __webpack_require__(/*! ../utils/descriptor-config */ "./projects/icons/src/utils/descriptor-config.ts");
var svg_tag_generator_1 = __webpack_require__(/*! ../utils/svg-tag-generator */ "./projects/icons/src/utils/svg-tag-generator.ts");
exports.ClrShapeUnknownStatus = (0, svg_tag_generator_1.clrIconSVG)("<circle class=\"clr-i-outline clr-i-outline-path-1\" cx=\"17.58\" cy=\"26.23\" r=\"1.4\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-2\" d=\"M24.7,13a5.18,5.18,0,0,0-2.16-3.56,7.26,7.26,0,0,0-5.71-1.09A11.34,11.34,0,0,0,12,10.44,1,1,0,1,0,13.26,12a9.32,9.32,0,0,1,3.94-1.72,5.29,5.29,0,0,1,4.16.74,3.21,3.21,0,0,1,1.35,2.19c.33,2.69-3.19,3.75-5.32,4.14l-.82.15v4.36a1,1,0,0,0,2,0V19.17C24.61,17.79,24.88,14.41,24.7,13Z\"/>");
exports.ClrShapeHome = (0, svg_tag_generator_1.clrIconSVG)("<path class=\"clr-i-outline clr-i-outline-path-1\" d=\"M33.71,17.29l-15-15a1,1,0,0,0-1.41,0l-15,15a1,1,0,0,0,1.41,1.41L18,4.41,32.29,18.71a1,1,0,0,0,1.41-1.41Z\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-2\" d=\"M28,32h-5V22H13V32H8V18L6,20V32a2,2,0,0,0,2,2h7V24h6V34h7a2,2,0,0,0,2-2V19.76l-2-2Z\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-1\" d=\"M33,19a1,1,0,0,1-.71-.29L18,4.41,3.71,18.71a1,1,0,0,1-1.41-1.41l15-15a1,1,0,0,1,1.41,0l15,15A1,1,0,0,1,33,19Z\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-2\" d=\"M18,7.79,6,19.83V32a2,2,0,0,0,2,2h7V24h6V34h7a2,2,0,0,0,2-2V19.76Z\"/>");
exports.ClrShapeCog = (0, svg_tag_generator_1.clrIconSVG)("<path class=\"clr-i-outline clr-i-outline-path-1\" d=\"M18.1,11c-3.9,0-7,3.1-7,7s3.1,7,7,7c3.9,0,7-3.1,7-7S22,11,18.1,11z M18.1,23c-2.8,0-5-2.2-5-5s2.2-5,5-5c2.8,0,5,2.2,5,5S20.9,23,18.1,23z\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-2\" d=\"M32.8,14.7L30,13.8l-0.6-1.5l1.4-2.6c0.3-0.6,0.2-1.4-0.3-1.9l-2.4-2.4c-0.5-0.5-1.3-0.6-1.9-0.3l-2.6,1.4l-1.5-0.6l-0.9-2.8C21,2.5,20.4,2,19.7,2h-3.4c-0.7,0-1.3,0.5-1.4,1.2L14,6c-0.6,0.1-1.1,0.3-1.6,0.6L9.8,5.2C9.2,4.9,8.4,5,7.9,5.5L5.5,7.9C5,8.4,4.9,9.2,5.2,9.8l1.3,2.5c-0.2,0.5-0.4,1.1-0.6,1.6l-2.8,0.9C2.5,15,2,15.6,2,16.3v3.4c0,0.7,0.5,1.3,1.2,1.5L6,22.1l0.6,1.5l-1.4,2.6c-0.3,0.6-0.2,1.4,0.3,1.9l2.4,2.4c0.5,0.5,1.3,0.6,1.9,0.3l2.6-1.4l1.5,0.6l0.9,2.9c0.2,0.6,0.8,1.1,1.5,1.1h3.4c0.7,0,1.3-0.5,1.5-1.1l0.9-2.9l1.5-0.6l2.6,1.4c0.6,0.3,1.4,0.2,1.9-0.3l2.4-2.4c0.5-0.5,0.6-1.3,0.3-1.9l-1.4-2.6l0.6-1.5l2.9-0.9c0.6-0.2,1.1-0.8,1.1-1.5v-3.4C34,15.6,33.5,14.9,32.8,14.7z M32,19.4l-3.6,1.1L28.3,21c-0.3,0.7-0.6,1.4-0.9,2.1l-0.3,0.5l1.8,3.3l-2,2l-3.3-1.8l-0.5,0.3c-0.7,0.4-1.4,0.7-2.1,0.9l-0.5,0.1L19.4,32h-2.8l-1.1-3.6L15,28.3c-0.7-0.3-1.4-0.6-2.1-0.9l-0.5-0.3l-3.3,1.8l-2-2l1.8-3.3l-0.3-0.5c-0.4-0.7-0.7-1.4-0.9-2.1l-0.1-0.5L4,19.4v-2.8l3.4-1l0.2-0.5c0.2-0.8,0.5-1.5,0.9-2.2l0.3-0.5L7.1,9.1l2-2l3.2,1.8l0.5-0.3c0.7-0.4,1.4-0.7,2.2-0.9l0.5-0.2L16.6,4h2.8l1.1,3.5L21,7.7c0.7,0.2,1.4,0.5,2.1,0.9l0.5,0.3l3.3-1.8l2,2l-1.8,3.3l0.3,0.5c0.4,0.7,0.7,1.4,0.9,2.1l0.1,0.5l3.6,1.1V19.4z\"/>\n                <path class=\"clr-i-outline--badged clr-i-outline-path-1--badged\" d=\"M11.1,18c0,3.9,3.1,7,7,7c3.9,0,7-3.1,7-7s-3.1-7-7-7C14.2,11,11.1,14.1,11.1,18z M23.1,18c0,2.8-2.2,5-5,5c-2.8,0-5-2.2-5-5s2.2-5,5-5C20.9,13,23.1,15.2,23.1,18z\"/>\n                <path class=\"clr-i-outline--badged clr-i-outline-path-2--badged\" d=\"M32.8,14.7L30,13.8l-0.1-0.3c-0.8,0-1.6-0.2-2.4-0.4c0.3,0.6,0.6,1.3,0.8,1.9l0.1,0.5l3.6,1.1v2.8l-3.6,1.1L28.3,21c-0.3,0.7-0.6,1.4-0.9,2.1l-0.3,0.5l1.8,3.3l-2,2l-3.3-1.8l-0.5,0.3c-0.7,0.4-1.4,0.7-2.1,0.9l-0.5,0.1L19.4,32h-2.8l-1.1-3.6L15,28.3c-0.7-0.3-1.4-0.6-2.1-0.9l-0.5-0.3l-3.3,1.8l-2-2l1.8-3.3l-0.3-0.5c-0.4-0.7-0.7-1.4-0.9-2.1l-0.1-0.5L4,19.4v-2.8l3.4-1l0.2-0.5c0.2-0.8,0.5-1.5,0.9-2.2l0.3-0.5L7.1,9.1l2-2l3.2,1.8l0.5-0.3c0.7-0.4,1.4-0.7,2.2-0.9l0.5-0.2L16.6,4h2.8l1.1,3.5L21,7.7c0.7,0.2,1.3,0.5,1.9,0.8c-0.3-0.8-0.4-1.6-0.4-2.5l-0.4-0.2l-0.9-2.8C21,2.5,20.4,2,19.7,2h-3.4c-0.7,0-1.3,0.5-1.4,1.2L14,6c-0.6,0.1-1.1,0.3-1.6,0.6L9.8,5.2C9.2,4.9,8.4,5,7.9,5.5L5.5,7.9C5,8.4,4.9,9.2,5.2,9.8l1.3,2.5c-0.2,0.5-0.4,1.1-0.6,1.6l-2.8,0.9C2.5,15,2,15.6,2,16.3v3.4c0,0.7,0.5,1.3,1.2,1.5L6,22.1l0.6,1.5l-1.4,2.6c-0.3,0.6-0.2,1.4,0.3,1.9l2.4,2.4c0.5,0.5,1.3,0.6,1.9,0.3l2.6-1.4l1.5,0.6l0.9,2.9c0.2,0.6,0.8,1.1,1.5,1.1h3.4c0.7,0,1.3-0.5,1.5-1.1l0.9-2.9l1.5-0.6l2.6,1.4c0.6,0.3,1.4,0.2,1.9-0.3l2.4-2.4c0.5-0.5,0.6-1.3,0.3-1.9l-1.4-2.6l0.6-1.5l2.9-0.9c0.6-0.2,1.1-0.8,1.1-1.5v-3.4C34,15.6,33.5,14.9,32.8,14.7z\"/>\n                <circle class=\"clr-i-outline--badged clr-i-outline-path-3--badged clr-i-badge\" cx=\"30\" cy=\"6\" r=\"5\"/>\n                <path class=\"clr-i-outline--alerted clr-i-outline-path-1--alerted\" d=\"M33.7,15.4h-5.3v0.1l3.6,1.1v2.8l-3.6,1.1L28.3,21c-0.3,0.7-0.6,1.4-0.9,2.1l-0.3,0.5l1.8,3.3l-2,2l-3.3-1.8l-0.5,0.3c-0.7,0.4-1.4,0.7-2.1,0.9l-0.5,0.1L19.4,32h-2.8l-1.1-3.6L15,28.3c-0.7-0.3-1.4-0.6-2.1-0.9l-0.5-0.3l-3.3,1.8l-2-2l1.8-3.3l-0.3-0.5c-0.4-0.7-0.7-1.4-0.9-2.1l-0.1-0.5L4,19.4v-2.8l3.4-1l0.2-0.5c0.2-0.8,0.5-1.5,0.9-2.2l0.3-0.5L7.1,9.1l2-2l3.2,1.8l0.5-0.3c0.7-0.4,1.4-0.7,2.2-0.9l0.5-0.2L16.6,4h2.8l1.1,3.4l1.4-2.3l-0.6-2C21,2.4,20.4,2,19.7,2h-3.4c-0.7,0-1.3,0.5-1.4,1.2L14,6c-0.6,0.1-1.1,0.3-1.6,0.6L9.8,5.2C9.2,4.9,8.4,5,7.9,5.5L5.5,7.9C5,8.4,4.9,9.2,5.2,9.8l1.3,2.5c-0.2,0.5-0.4,1.1-0.6,1.6l-2.8,0.9C2.5,15,2,15.6,2,16.3v3.4c0,0.7,0.5,1.3,1.2,1.5L6,22.1l0.6,1.5l-1.4,2.6c-0.3,0.6-0.2,1.4,0.3,1.9l2.4,2.4c0.5,0.5,1.3,0.6,1.9,0.3l2.6-1.4l1.5,0.6l0.9,2.9c0.2,0.6,0.8,1.1,1.5,1.1h3.4c0.7,0,1.3-0.5,1.5-1.1l0.9-2.9l1.5-0.6l2.6,1.4c0.6,0.3,1.4,0.2,1.9-0.3l2.4-2.4c0.5-0.5,0.6-1.3,0.3-1.9l-1.4-2.6l0.6-1.5l2.9-0.9c0.6-0.2,1.1-0.8,1.1-1.5v-3.4C34,16,33.9,15.7,33.7,15.4z\"/>\n                <path class=\"clr-i-outline--alerted clr-i-outline-path-2--alerted\" d=\"M18.1,23c-2.8,0-5-2.2-5-5s2.2-5,5-5c0.2,0,0.5,0,0.7,0.1c-0.2-0.6-0.3-1.3-0.2-2h-0.5c-3.9,0-7,3.1-7,7c0,3.9,3.1,7,7,7c3.9,0,7-3.1,7-7c0-0.9-0.2-1.8-0.5-2.6h-2.2c0.5,0.8,0.7,1.6,0.7,2.5C23.1,20.8,20.9,23,18.1,23z\"/>\n                <path class=\"clr-i-outline--alerted clr-i-outline-path-3--alerted clr-i-alert\" d=\"M26.9,1.1L21.1,11c-0.4,0.6-0.2,1.4,0.3,1.8c0.2,0.2,0.5,0.2,0.8,0.2h11.5c0.7,0,1.3-0.5,1.3-1.2c0-0.3-0.1-0.5-0.2-0.8l-5.7-9.9c-0.4-0.6-1.1-0.8-1.8-0.5C27.1,0.8,27,1,26.9,1.1z\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-1\" d=\"M32.57,15.72l-3.35-1a11.65,11.65,0,0,0-.95-2.33l1.64-3.07a.61.61,0,0,0-.11-.72L27.41,6.2a.61.61,0,0,0-.72-.11L23.64,7.72a11.62,11.62,0,0,0-2.36-1l-1-3.31A.61.61,0,0,0,19.69,3H16.31a.61.61,0,0,0-.58.43l-1,3.3a11.63,11.63,0,0,0-2.38,1l-3-1.62a.61.61,0,0,0-.72.11L6.2,8.59a.61.61,0,0,0-.11.72l1.62,3a11.63,11.63,0,0,0-1,2.37l-3.31,1a.61.61,0,0,0-.43.58v3.38a.61.61,0,0,0,.43.58l3.33,1a11.62,11.62,0,0,0,1,2.33L6.09,26.69a.61.61,0,0,0,.11.72L8.59,29.8a.61.61,0,0,0,.72.11l3.09-1.65a11.65,11.65,0,0,0,2.3.94l1,3.37a.61.61,0,0,0,.58.43h3.38a.61.61,0,0,0,.58-.43l1-3.38a11.63,11.63,0,0,0,2.28-.94l3.11,1.66a.61.61,0,0,0,.72-.11l2.39-2.39a.61.61,0,0,0,.11-.72l-1.66-3.1a11.63,11.63,0,0,0,.95-2.29l3.37-1a.61.61,0,0,0,.43-.58V16.31A.61.61,0,0,0,32.57,15.72ZM18,23.5A5.5,5.5,0,1,1,23.5,18,5.5,5.5,0,0,1,18,23.5Z\"/>\n                <path class=\"clr-i-solid--badged clr-i-solid-path-1--badged\" d=\"M32.57,15.72l-3.35-1a12.12,12.12,0,0,0-.47-1.32,7.49,7.49,0,0,1-6.14-6.16,11.82,11.82,0,0,0-1.33-.48l-1-3.31A.61.61,0,0,0,19.69,3H16.31a.61.61,0,0,0-.58.43l-1,3.3a11.63,11.63,0,0,0-2.38,1l-3-1.62a.61.61,0,0,0-.72.11L6.2,8.59a.61.61,0,0,0-.11.72l1.62,3a11.63,11.63,0,0,0-1,2.37l-3.31,1a.61.61,0,0,0-.43.58v3.38a.61.61,0,0,0,.43.58l3.33,1a11.62,11.62,0,0,0,1,2.33L6.09,26.69a.61.61,0,0,0,.11.72L8.59,29.8a.61.61,0,0,0,.72.11l3.09-1.65a11.65,11.65,0,0,0,2.3.94l1,3.37a.61.61,0,0,0,.58.43h3.38a.61.61,0,0,0,.58-.43l1-3.38a11.63,11.63,0,0,0,2.28-.94l3.11,1.66a.61.61,0,0,0,.72-.11l2.39-2.39a.61.61,0,0,0,.11-.72l-1.66-3.1a11.63,11.63,0,0,0,.95-2.29l3.37-1a.61.61,0,0,0,.43-.58V16.31A.61.61,0,0,0,32.57,15.72ZM18,23.5A5.5,5.5,0,1,1,23.5,18,5.5,5.5,0,0,1,18,23.5Z\"/>\n                <circle class=\"clr-i-solid--badged clr-i-solid-path-2--badged clr-i-badge\" cx=\"30\" cy=\"6\" r=\"5\"/>\n                <path class=\"clr-i-solid--alerted clr-i-solid-path-1--alerted\" d=\"M32.57,15.72,31.5,15.4H22.85A5.5,5.5,0,1,1,18,12.5a5.53,5.53,0,0,1,.65,0A3.68,3.68,0,0,1,19,9.89l2.09-3.62-.86-2.83A.61.61,0,0,0,19.69,3H16.31a.61.61,0,0,0-.58.43l-1,3.3a11.63,11.63,0,0,0-2.38,1l-3-1.62a.61.61,0,0,0-.72.11L6.2,8.59a.61.61,0,0,0-.11.72l1.62,3a11.63,11.63,0,0,0-1,2.37l-3.31,1a.61.61,0,0,0-.43.58v3.38a.61.61,0,0,0,.43.58l3.33,1a11.62,11.62,0,0,0,1,2.33L6.09,26.69a.61.61,0,0,0,.11.72L8.59,29.8a.61.61,0,0,0,.72.11l3.09-1.65a11.65,11.65,0,0,0,2.3.94l1,3.37a.61.61,0,0,0,.58.43h3.38a.61.61,0,0,0,.58-.43l1-3.38a11.63,11.63,0,0,0,2.28-.94l3.11,1.66a.61.61,0,0,0,.72-.11l2.39-2.39a.61.61,0,0,0,.11-.72l-1.66-3.1a11.63,11.63,0,0,0,.95-2.29l3.37-1a.61.61,0,0,0,.43-.58V16.31A.61.61,0,0,0,32.57,15.72Z\"/>\n                <path class=\"clr-i-solid--alerted clr-i-solid-path-2--alerted clr-i-alert\" d=\"M26.85,1.14,21.13,11A1.28,1.28,0,0,0,22.23,13H33.68A1.28,1.28,0,0,0,34.78,11L29.06,1.14A1.28,1.28,0,0,0,26.85,1.14Z\"/>");
exports.ClrShapeCheck = (0, svg_tag_generator_1.clrIconSVG)("<path class=\"clr-i-outline clr-i-outline-path-1\" d=\"M13.72,27.69,3.29,17.27a1,1,0,0,1,1.41-1.41l9,9L31.29,7.29a1,1,0,0,1,1.41,1.41Z\"/>");
exports.ClrShapeTimes = (0, svg_tag_generator_1.clrIconSVG)("<path class=\"clr-i-outline clr-i-outline-path-1\" d=\"M19.41,18l8.29-8.29a1,1,0,0,0-1.41-1.41L18,16.59,9.71,8.29A1,1,0,0,0,8.29,9.71L16.59,18,8.29,26.29a1,1,0,1,0,1.41,1.41L18,19.41l8.29,8.29a1,1,0,0,0,1.41-1.41Z\"/>");
exports.ClrShapeExclamationTriangle = (0, svg_tag_generator_1.clrIconSVG)("<path class=\"clr-i-outline clr-i-outline-path-1\" d=\"M18,21.32a1.3,1.3,0,0,0,1.3-1.3V14a1.3,1.3,0,1,0-2.6,0v6A1.3,1.3,0,0,0,18,21.32Z\"/>\n                <circle class=\"clr-i-outline clr-i-outline-path-2\" cx=\"17.95\" cy=\"24.27\" r=\"1.5\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-3\" d=\"M30.33,25.54,20.59,7.6a3,3,0,0,0-5.27,0L5.57,25.54A3,3,0,0,0,8.21,30H27.69a3,3,0,0,0,2.64-4.43Zm-1.78,1.94a1,1,0,0,1-.86.49H8.21a1,1,0,0,1-.88-1.48L17.07,8.55a1,1,0,0,1,1.76,0l9.74,17.94A1,1,0,0,1,28.55,27.48Z\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-1\" d=\"M30.33,25.54,20.59,7.6a3,3,0,0,0-5.27,0L5.57,25.54A3,3,0,0,0,8.21,30H27.69a3,3,0,0,0,2.64-4.43ZM16.46,12.74a1.49,1.49,0,0,1,3,0v6.89a1.49,1.49,0,1,1-3,0ZM18,26.25a1.72,1.72,0,1,1,1.72-1.72A1.72,1.72,0,0,1,18,26.25Z\"/>");
exports.ClrShapeExclamationCircle = (0, svg_tag_generator_1.clrIconSVG)("<path class=\"clr-i-outline clr-i-outline-path-1\" d=\"M18,6A12,12,0,1,0,30,18,12,12,0,0,0,18,6Zm0,22A10,10,0,1,1,28,18,10,10,0,0,1,18,28Z\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-2\" d=\"M18,20.07a1.3,1.3,0,0,1-1.3-1.3v-6a1.3,1.3,0,1,1,2.6,0v6A1.3,1.3,0,0,1,18,20.07Z\"/>\n                <circle class=\"clr-i-outline clr-i-outline-path-3\" cx=\"17.95\" cy=\"23.02\" r=\"1.5\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-1\" d=\"M18,6A12,12,0,1,0,30,18,12,12,0,0,0,18,6Zm-1.49,6a1.49,1.49,0,0,1,3,0v6.89a1.49,1.49,0,1,1-3,0ZM18,25.5a1.72,1.72,0,1,1,1.72-1.72A1.72,1.72,0,0,1,18,25.5Z\"/>");
exports.ClrShapeCheckCircle = (0, svg_tag_generator_1.clrIconSVG)("<path class=\"clr-i-outline clr-i-outline-path-1\" d=\"M18,6A12,12,0,1,0,30,18,12,12,0,0,0,18,6Zm0,22A10,10,0,1,1,28,18,10,10,0,0,1,18,28Z\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-2\" d=\"M16.34,23.74l-5-5a1,1,0,0,1,1.41-1.41l3.59,3.59,6.78-6.78a1,1,0,0,1,1.41,1.41Z\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-1\" d=\"M30,18A12,12,0,1,1,18,6,12,12,0,0,1,30,18Zm-4.77-2.16a1.4,1.4,0,0,0-2-2l-6.77,6.77L13,17.16a1.4,1.4,0,0,0-2,2l5.45,5.45Z\"/>");
exports.ClrShapeInfoCircle = (0, svg_tag_generator_1.clrIconSVG)("<circle class=\"clr-i-outline clr-i-outline-path-1\"  cx=\"17.93\" cy=\"11.9\" r=\"1.4\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-2\"  d=\"M21,23H19V15H16a1,1,0,0,0,0,2h1v6H15a1,1,0,1,0,0,2h6a1,1,0,0,0,0-2Z\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-3\"  d=\"M18,6A12,12,0,1,0,30,18,12,12,0,0,0,18,6Zm0,22A10,10,0,1,1,28,18,10,10,0,0,1,18,28Z\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-1\" d=\"M18,6A12,12,0,1,0,30,18,12,12,0,0,0,18,6Zm-2,5.15a2,2,0,1,1,2,2A2,2,0,0,1,15.9,11.15ZM23,24a1,1,0,0,1-1,1H15a1,1,0,1,1,0-2h2V17H16a1,1,0,0,1,0-2h4v8h2A1,1,0,0,1,23,24Z\"/>");
exports.ClrShapeInfoStandard = (0, svg_tag_generator_1.clrIconSVG)("<circle class=\"clr-i-outline clr-i-outline-path-1\" cx=\"17.97\" cy=\"10.45\" r=\"1.4\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-2\" d=\"M21,25H19V14.1H16a1,1,0,0,0,0,2h1V25H15a1,1,0,0,0,0,2h6a1,1,0,0,0,0-2Z\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-3\" d=\"M18,34A16,16,0,1,1,34,18,16,16,0,0,1,18,34ZM18,4A14,14,0,1,0,32,18,14,14,0,0,0,18,4Z\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-1\" d=\"M18,2.1a16,16,0,1,0,16,16A16,16,0,0,0,18,2.1Zm-.1,5.28a2,2,0,1,1-2,2A2,2,0,0,1,17.9,7.38Zm3.6,21.25h-7a1.4,1.4,0,1,1,0-2.8h2.1v-9.2H15a1.4,1.4,0,1,1,0-2.8h4.4v12h2.1a1.4,1.4,0,1,1,0,2.8Z\"/>");
exports.ClrShapeSuccessStandard = (0, svg_tag_generator_1.clrIconSVG)("<path class=\"clr-i-outline clr-i-outline-path-1\" d=\"M18,2A16,16,0,1,0,34,18,16,16,0,0,0,18,2Zm0,30A14,14,0,1,1,32,18,14,14,0,0,1,18,32Z\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-2\" d=\"M28,12.1a1,1,0,0,0-1.41,0L15.49,23.15l-6-6A1,1,0,0,0,8,18.53L15.49,26,28,13.52A1,1,0,0,0,28,12.1Z\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-1\" d=\"M18,2A16,16,0,1,0,34,18,16,16,0,0,0,18,2ZM28.45,12.63,15.31,25.76,7.55,18a1.4,1.4,0,0,1,2-2l5.78,5.78L26.47,10.65a1.4,1.4,0,1,1,2,2Z\"/>");
exports.ClrShapeErrorStandard = (0, svg_tag_generator_1.clrIconSVG)("<circle class=\"clr-i-outline clr-i-outline-path-1\" cx=\"18\" cy=\"26.06\" r=\"1.33\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-2\" d=\"M18,22.61a1,1,0,0,1-1-1v-12a1,1,0,1,1,2,0v12A1,1,0,0,1,18,22.61Z\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-3\" d=\"M18,34A16,16,0,1,1,34,18,16,16,0,0,1,18,34ZM18,4A14,14,0,1,0,32,18,14,14,0,0,0,18,4Z\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-1\" d=\"M18,2.1a16,16,0,1,0,16,16A16,16,0,0,0,18,2.1ZM16.6,8.8a1.4,1.4,0,0,1,2.8,0v12a1.4,1.4,0,0,1-2.8,0ZM18,28.6a1.8,1.8,0,1,1,1.8-1.8A1.8,1.8,0,0,1,18,28.6Z\"/>");
exports.ClrShapeWarningStandard = (0, svg_tag_generator_1.clrIconSVG)("<circle class=\"clr-i-outline clr-i-outline-path-1\" cx=\"18\" cy=\"26.06\" r=\"1.33\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-2\" d=\"M18,22.61a1,1,0,0,1-1-1v-12a1,1,0,1,1,2,0v12A1,1,0,0,1,18,22.61Z\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-3\" d=\"M15.0620782,1.681196 C15.6298819,0.649266355 16.7109091,0.0102219396 17.885,0.0102219396 C19.0590909,0.0102219396 20.1401181,0.649266355 20.7086433,1.68252129 L34.598644,27.2425225 C35.1407746,28.2401397 35.1174345,29.4495373 34.5372161,30.4254943 C33.9569977,31.4014514 32.905671,31.9996984 31.77,32 L4.02239323,31.9997492 C2.87409009,32.0254699 1.79902843,31.4375753 1.20106335,30.4569126 C0.603098265,29.4762499 0.572777899,28.2513179 1.12207818,27.241196 L15.0620782,1.681196 Z M2.87850767,28.1977282 C2.67060966,28.5800376 2.6820975,29.0441423 2.9086557,29.4156977 C3.1352139,29.7872532 3.5425354,30.0099959 4,30 L31.7697344,30 C32.1999191,29.9998858 32.5982478,29.7732208 32.8180821,29.4034482 C33.0379164,29.0336757 33.0467595,28.5754567 32.8413567,28.1974787 L18.9538739,2.64208195 C18.7394236,2.25234436 18.3298419,2.01022194 17.885,2.01022194 C17.4406889,2.01022194 17.0315538,2.25176692 16.8168946,2.64068753 L2.87850767,28.1977282 Z\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-1\" d=\"M34.6,29.21,20.71,3.65a3.22,3.22,0,0,0-5.66,0L1.17,29.21A3.22,3.22,0,0,0,4,34H31.77a3.22,3.22,0,0,0,2.83-4.75ZM16.6,10a1.4,1.4,0,0,1,2.8,0v12a1.4,1.4,0,0,1-2.8,0ZM18,29.85a1.8,1.8,0,1,1,1.8-1.8A1.8,1.8,0,0,1,18,29.85Z\"/>");
exports.ClrShapeHelpInfo = (0, svg_tag_generator_1.clrIconSVG)("<path d=\"M25.39,25.45a1,1,0,0,0-1.38.29c-1.41,2.16-4,4.81-6.31,5.7s-4.12.57-4.84,0c-.31-.27-1.12-1-.43-3.49.46-1.66,3.32-9.48,4-11.38l-2.18.28c-.69,1.86-3.29,8.84-3.76,10.58-.68,2.49-.34,4.3,1.09,5.56A5.59,5.59,0,0,0,15,34a9.53,9.53,0,0,0,3.45-.7c2.79-1.09,5.72-4.12,7.26-6.47A1,1,0,0,0,25.39,25.45Z\" class=\"clr-i-outline clr-i-outline-path-1\" />\n            <path d=\"M19.3,11a4.5,4.5,0,1,0-4.5-4.5A4.5,4.5,0,0,0,19.3,11Zm0-7a2.5,2.5,0,1,1-2.5,2.5A2.5,2.5,0,0,1,19.3,4Z\" class=\"clr-i-outline clr-i-outline-path-2\" />\n            <path d=\"M11.81,15c.06,0,6.27-.82,7.73-1,.65-.1,1.14,0,1.3.15s.21.8-.07,1.68c-.61,1.86-3.69,11-4.59,13.71a8,8,0,0,0,1.29-.38,7.32,7.32,0,0,0,1.15-.6C19.85,25,22.15,18.1,22.67,16.52s.39-2.78-.3-3.6a3.16,3.16,0,0,0-3.08-.83c-1.43.15-7.47.94-7.73,1a1,1,0,0,0,.26,2Z\" class=\"clr-i-outline clr-i-outline-path-3\" />\n            <circle cx=\"20.75\" cy=\"6\" r=\"4\" class=\"clr-i-solid clr-i-solid-path-1\" />\n            <path d=\"M24.84,26.23a1,1,0,0,0-1.4.29,16.6,16.6,0,0,1-3.51,3.77c-.33.25-1.56,1.2-2.08,1-.36-.11-.15-.82-.08-1.12l.53-1.57c.22-.64,4.05-12,4.47-13.3.62-1.9.35-3.77-2.48-3.32-.77.08-8.58,1.09-8.72,1.1a1,1,0,0,0,.13,2s3-.39,3.33-.42a.88.88,0,0,1,.85.44,2.47,2.47,0,0,1-.07,1.71c-.26,1-4.37,12.58-4.5,13.25a2.78,2.78,0,0,0,1.18,3,5,5,0,0,0,3.08.83h0a8.53,8.53,0,0,0,3.09-.62c2.49-1,5.09-3.66,6.46-5.75A1,1,0,0,0,24.84,26.23Z\" class=\"clr-i-solid clr-i-solid-path-2\" />");
exports.ClrShapeBars = (0, svg_tag_generator_1.clrIconSVG)("<path class=\"clr-i-outline clr-i-outline-path-1\" d=\"M32,29H4a1,1,0,0,1,0-2H32a1,1,0,0,1,0,2Z\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-2\" d=\"M32,19H4a1,1,0,0,1,0-2H32a1,1,0,0,1,0,2Z\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-3\" d=\"M32,9H4A1,1,0,0,1,4,7H32a1,1,0,0,1,0,2Z\"/>");
exports.ClrShapeUser = (0, svg_tag_generator_1.clrIconSVG)("<path d=\"M18,17a7,7,0,1,0-7-7A7,7,0,0,0,18,17ZM18,5a5,5,0,1,1-5,5A5,5,0,0,1,18,5Z\" class=\"clr-i-outline clr-i-outline-path-1\" />\n            <path d=\"M30.47,24.37a17.16,17.16,0,0,0-24.93,0A2,2,0,0,0,5,25.74V31a2,2,0,0,0,2,2H29a2,2,0,0,0,2-2V25.74A2,2,0,0,0,30.47,24.37ZM29,31H7V25.73a15.17,15.17,0,0,1,22,0h0Z\" class=\"clr-i-outline clr-i-outline-path-2\" />\n            <path d=\"M30.47,24.37a17.16,17.16,0,0,0-24.93,0A2,2,0,0,0,5,25.74V31a2,2,0,0,0,2,2H29a2,2,0,0,0,2-2V25.74A2,2,0,0,0,30.47,24.37ZM29,31H7V25.73a15.17,15.17,0,0,1,22,0h0Z\" class=\"clr-i-outline--alerted clr-i-outline-path-1--alerted\" />\n            <path d=\"M18,17a7,7,0,0,0,4.45-1.6h-.22A3.68,3.68,0,0,1,20,14.6a5,5,0,1,1,1.24-8.42l1-1.76A7,7,0,1,0,18,17Z\" class=\"clr-i-outline--alerted clr-i-outline-path-2--alerted\" />\n            <path d=\"M26.85,1.14,21.13,11A1.28,1.28,0,0,0,22.23,13H33.68A1.28,1.28,0,0,0,34.78,11L29.06,1.14A1.28,1.28,0,0,0,26.85,1.14Z\"  class=\"clr-i-outline--alerted clr-i-outline-path-3--alerted clr-i-alert\" />\n            <path d=\"M30.47,24.37a17.16,17.16,0,0,0-24.93,0A2,2,0,0,0,5,25.74V31a2,2,0,0,0,2,2H29a2,2,0,0,0,2-2V25.74A2,2,0,0,0,30.47,24.37ZM29,31H7V25.73a15.17,15.17,0,0,1,22,0h0Z\" class=\"clr-i-outline--badged clr-i-outline-path-1--badged\" />\n            <path d=\"M18,17a7,7,0,0,0,6.85-5.56,7.4,7.4,0,0,1-2.24-6.69A7,7,0,1,0,18,17ZM18,5a5,5,0,1,1-5,5A5,5,0,0,1,18,5Z\" class=\"clr-i-outline--badged clr-i-outline-path-2--badged\" />\n            <circle cx=\"30\" cy=\"6\" r=\"5\"  class=\"clr-i-outline--badged clr-i-outline-path-3--badged clr-i-badge\" />\n            <path d=\"M30.61,24.52a17.16,17.16,0,0,0-25.22,0,1.51,1.51,0,0,0-.39,1v6A1.5,1.5,0,0,0,6.5,33h23A1.5,1.5,0,0,0,31,31.5v-6A1.51,1.51,0,0,0,30.61,24.52Z\" class=\"clr-i-solid clr-i-solid-path-1\" />\n            <circle cx=\"18\" cy=\"10\" r=\"7\" class=\"clr-i-solid clr-i-solid-path-2\" />\n            <path d=\"M30.61,24.52a17.16,17.16,0,0,0-25.22,0,1.51,1.51,0,0,0-.39,1v6A1.5,1.5,0,0,0,6.5,33h23A1.5,1.5,0,0,0,31,31.5v-6A1.51,1.51,0,0,0,30.61,24.52Z\" class=\"clr-i-solid--alerted clr-i-solid-path-1--alerted\" />\n            <path d=\"M18,17a7,7,0,0,0,4.45-1.6h-.22A3.68,3.68,0,0,1,19,9.89l3.16-5.47A7,7,0,1,0,18,17Z\" class=\"clr-i-solid--alerted clr-i-solid-path-2--alerted\" />\n            <path d=\"M26.85,1.14,21.13,11A1.28,1.28,0,0,0,22.23,13H33.68A1.28,1.28,0,0,0,34.78,11L29.06,1.14A1.28,1.28,0,0,0,26.85,1.14Z\"  class=\"clr-i-solid--alerted clr-i-solid-path-3--alerted clr-i-alert\" />\n            <path d=\"M30.61,24.52a17.16,17.16,0,0,0-25.22,0,1.51,1.51,0,0,0-.39,1v6A1.5,1.5,0,0,0,6.5,33h23A1.5,1.5,0,0,0,31,31.5v-6A1.51,1.51,0,0,0,30.61,24.52Z\" class=\"clr-i-solid--badged clr-i-solid-path-1--badged\" />\n            <path d=\"M18,17a7,7,0,0,0,6.85-5.56,7.4,7.4,0,0,1-2.24-6.69A7,7,0,1,0,18,17Z\" class=\"clr-i-solid--badged clr-i-solid-path-2--badged\" />\n            <circle cx=\"30\" cy=\"6\" r=\"5\"  class=\"clr-i-solid--badged clr-i-solid-path-3--badged clr-i-badge\" />");
exports.ClrShapeAngle = (0, svg_tag_generator_1.clrIconSVG)("<path class=\"clr-i-outline clr-i-outline-path-1\" d=\"M29.52,22.52,18,10.6,6.48,22.52a1.7,1.7,0,0,0,2.45,2.36L18,15.49l9.08,9.39a1.7,1.7,0,0,0,2.45-2.36Z\"/>");
exports.ClrShapeFolder = (0, svg_tag_generator_1.clrIconSVG)("<path class=\"clr-i-outline clr-i-outline-path-1\" d=\"M30,9H16.42L14.11,5.82A2,2,0,0,0,12.49,5H6A2,2,0,0,0,4,7V29a2,2,0,0,0,2,2H30a2,2,0,0,0,2-2V11A2,2,0,0,0,30,9Zm0,20H6V13h7.31a2,2,0,0,0,2-2H6V7h6.49l2.61,3.59a1,1,0,0,0,.81.41H30Z\"/>\n                <path class=\"clr-i-outline--badged clr-i-outline-path-1--badged\" d=\"M30,13.5V29H6V13h7.31a2,2,0,0,0,2-2H6V7h6.49l2.61,3.59a1,1,0,0,0,.81.41h8.51a7.5,7.5,0,0,1-1.29-2H16.42L14.11,5.82A2,2,0,0,0,12.49,5H6A2,2,0,0,0,4,7V29a2,2,0,0,0,2,2H30a2,2,0,0,0,2-2V13.22A7.49,7.49,0,0,1,30,13.5Z\"/>\n                <circle class=\"clr-i-outline--badged clr-i-outline-path-2--badged clr-i-badge\" cx=\"30\" cy=\"6\" r=\"5\"/>\n                <path class=\"clr-i-outline--alerted clr-i-outline-path-1--alerted\" d=\"M30,15.4V29H6V13h7.31a2,2,0,0,0,2-2H6V7h6.49l2.61,3.59a1,1,0,0,0,.81.41h2.73A3.66,3.66,0,0,1,19,9.89L19.56,9H16.42L14.11,5.82A2,2,0,0,0,12.49,5H6A2,2,0,0,0,4,7V29a2,2,0,0,0,2,2H30a2,2,0,0,0,2-2V15.4Z\"/>\n                <path class=\"clr-i-outline--alerted clr-i-outline-path-2--alerted clr-i-alert\" d=\"M26.85,1.14,21.13,11A1.28,1.28,0,0,0,22.23,13H33.68A1.28,1.28,0,0,0,34.78,11L29.06,1.14A1.28,1.28,0,0,0,26.85,1.14Z\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-1\" d=\"M30,9H16.42L14.11,5.82A2,2,0,0,0,12.49,5H6A2,2,0,0,0,4,7V29a2,2,0,0,0,2,2H30a2,2,0,0,0,2-2V11A2,2,0,0,0,30,9ZM6,11V7h6.49l2.72,4Z\"/>\n                <path class=\"clr-i-solid--alerted clr-i-solid-path-1--alerted\" d=\"M22.23,15.4A3.68,3.68,0,0,1,19,9.89L19.56,9H16.42L14.11,5.82A2,2,0,0,0,12.49,5H6A2,2,0,0,0,4,7V29a2,2,0,0,0,2,2H30a2,2,0,0,0,2-2V15.4ZM6,11V7h6.49l2.72,4Z\"/>\n                <path class=\"clr-i-solid--alerted clr-i-solid-path-2--alerted clr-i-alert\" d=\"M26.85,1.14,21.13,11A1.28,1.28,0,0,0,22.23,13H33.68A1.28,1.28,0,0,0,34.78,11L29.06,1.14A1.28,1.28,0,0,0,26.85,1.14Z\"/>\n                <path class=\"clr-i-solid--badged clr-i-solid-path-1--badged\" d=\"M30,13.5A7.5,7.5,0,0,1,23.13,9H16.42L14.11,5.82A2,2,0,0,0,12.49,5H6A2,2,0,0,0,4,7V29a2,2,0,0,0,2,2H30a2,2,0,0,0,2-2V13.22A7.49,7.49,0,0,1,30,13.5ZM6,11V7h6.49l2.72,4Z\"/>\n                <circle class=\"clr-i-solid--badged clr-i-solid-path-2--badged clr-i-badge\" cx=\"30\" cy=\"6\" r=\"5\"/>");
exports.ClrShapeFolderOpen = (0, svg_tag_generator_1.clrIconSVG)("<path class=\"clr-i-outline clr-i-outline-path-1\" d=\"M35.32,13.74A1.71,1.71,0,0,0,33.87,13H11.17a2.59,2.59,0,0,0-2.25,1.52,1,1,0,0,0,0,.14L6,25V7h6.49l2.61,3.59a1,1,0,0,0,.81.41H32a2,2,0,0,0-2-2H16.42L14.11,5.82A2,2,0,0,0,12.49,5H6A2,2,0,0,0,4,7V29.69A1.37,1.37,0,0,0,5.41,31H30.34a1,1,0,0,0,1-.72l4.19-15.1A1.64,1.64,0,0,0,35.32,13.74ZM29.55,29H6.9l3.88-13.81a.66.66,0,0,1,.38-.24H33.49Z\"/>\n                <path class=\"clr-i-outline--badged clr-i-outline-path-1--badged\" d=\"M35.32,13.74A1.71,1.71,0,0,0,33.87,13H11.17a2.59,2.59,0,0,0-2.25,1.52,1,1,0,0,0,0,.14L6,25V7h6.49l2.61,3.59a1,1,0,0,0,.81.41h8.52a7.49,7.49,0,0,1-1.29-2H16.42L14.11,5.82A2,2,0,0,0,12.49,5H6A2,2,0,0,0,4,7V29.69A1.37,1.37,0,0,0,5.41,31H30.34a1,1,0,0,0,1-.72l4.19-15.1A1.64,1.64,0,0,0,35.32,13.74ZM29.55,29H6.9l3.88-13.81a.66.66,0,0,1,.38-.24H33.49Z\"/>\n                <circle class=\"clr-i-outline--badged clr-i-outline-path-2--badged clr-i-badge\" cx=\"30\" cy=\"6\" r=\"5\"/>\n                <path class=\"clr-i-outline--alerted clr-i-outline-path-1--alerted\" d=\"M33.68,15.4h-.3L29.55,29H6.9l3.88-13.81a.66.66,0,0,1,.38-.24h9.42A3.67,3.67,0,0,1,19,13.56a3.63,3.63,0,0,1-.26-.56H11.17a2.59,2.59,0,0,0-2.25,1.52,1,1,0,0,0,0,.14L6,25V7h6.49l2.61,3.59a1,1,0,0,0,.81.41h2.73A3.66,3.66,0,0,1,19,9.89L19.56,9H16.42L14.11,5.82A2,2,0,0,0,12.49,5H6A2,2,0,0,0,4,7V29.69A1.37,1.37,0,0,0,5.41,31H30.34a1,1,0,0,0,1-.72l4.19-15.1a1.68,1.68,0,0,0,.07-.32A3.67,3.67,0,0,1,33.68,15.4Z\"/>\n                <path class=\"clr-i-outline--alerted clr-i-outline-path-2--alerted clr-i-alert\" d=\"M26.85,1.14,21.13,11A1.28,1.28,0,0,0,22.23,13H33.68A1.28,1.28,0,0,0,34.78,11L29.06,1.14A1.28,1.28,0,0,0,26.85,1.14Z\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-1\" d=\"M35.32,13.74A1.71,1.71,0,0,0,33.87,13H11.17a2.59,2.59,0,0,0-2.25,1.52,1,1,0,0,0,0,.14L6,25V7h6.49l2.61,3.59a1,1,0,0,0,.81.41H32a2,2,0,0,0-2-2H16.42L14.11,5.82A2,2,0,0,0,12.49,5H6A2,2,0,0,0,4,7V29.69A1.37,1.37,0,0,0,5.41,31H30.34a1,1,0,0,0,1-.72l4.19-15.1A1.64,1.64,0,0,0,35.32,13.74Z\"/>\n                <path class=\"clr-i-solid--alerted clr-i-solid-path-1--alerted\" d=\"M33.68,15.4H22.23A3.69,3.69,0,0,1,19,13.56a3.63,3.63,0,0,1-.26-.56H11.17a2.59,2.59,0,0,0-2.25,1.52,1,1,0,0,0,0,.14L6,25V7h6.49l2.61,3.59a1,1,0,0,0,.81.41h2.73A3.66,3.66,0,0,1,19,9.89L19.56,9H16.42L14.11,5.82A2,2,0,0,0,12.49,5H6A2,2,0,0,0,4,7V29.69A1.37,1.37,0,0,0,5.41,31H30.34a1,1,0,0,0,1-.72l4.19-15.1a1.68,1.68,0,0,0,.07-.32A3.67,3.67,0,0,1,33.68,15.4Z\"/>\n                <path class=\"clr-i-solid--alerted clr-i-solid-path-2--alerted clr-i-alert\" d=\"M26.85,1.14,21.13,11A1.28,1.28,0,0,0,22.23,13H33.68A1.28,1.28,0,0,0,34.78,11L29.06,1.14A1.28,1.28,0,0,0,26.85,1.14Z\"/>\n                <path class=\"clr-i-solid--badged clr-i-solid-path-1--badged\" d=\"M35.32,13.74A1.71,1.71,0,0,0,33.87,13H11.17a2.59,2.59,0,0,0-2.25,1.52,1,1,0,0,0,0,.14L6,25V7h6.49l2.61,3.59a1,1,0,0,0,.81.41h8.52a7.49,7.49,0,0,1-1.31-2H16.42L14.11,5.82A2,2,0,0,0,12.49,5H6A2,2,0,0,0,4,7V29.69A1.37,1.37,0,0,0,5.41,31H30.34a1,1,0,0,0,1-.72l4.19-15.1A1.64,1.64,0,0,0,35.32,13.74Z\"/>\n                <circle class=\"clr-i-solid--badged clr-i-solid-path-2--badged clr-i-badge\" cx=\"30\" cy=\"6\" r=\"5\"/>");
exports.ClrShapeBell = (0, svg_tag_generator_1.clrIconSVG)("<path class=\"clr-i-outline clr-i-outline-path-1\" d=\"M32.51,27.83A14.4,14.4,0,0,1,30,24.9a12.63,12.63,0,0,1-1.35-4.81V15.15A10.81,10.81,0,0,0,19.21,4.4V3.11a1.33,1.33,0,1,0-2.67,0V4.42A10.81,10.81,0,0,0,7.21,15.15v4.94A12.63,12.63,0,0,1,5.86,24.9a14.4,14.4,0,0,1-2.47,2.93,1,1,0,0,0-.34.75v1.36a1,1,0,0,0,1,1h27.8a1,1,0,0,0,1-1V28.58A1,1,0,0,0,32.51,27.83ZM5.13,28.94a16.17,16.17,0,0,0,2.44-3,14.24,14.24,0,0,0,1.65-5.85V15.15a8.74,8.74,0,1,1,17.47,0v4.94a14.24,14.24,0,0,0,1.65,5.85,16.17,16.17,0,0,0,2.44,3Z\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-2\" d=\"M18,34.28A2.67,2.67,0,0,0,20.58,32H15.32A2.67,2.67,0,0,0,18,34.28Z\"/>\n                <path class=\"clr-i-outline--badged clr-i-outline-path-1--badged\" d=\"M18,34.28A2.67,2.67,0,0,0,20.58,32H15.32A2.67,2.67,0,0,0,18,34.28Z\"/>\n                <path class=\"clr-i-outline--badged clr-i-outline-path-2--badged\" d=\"M32.51,27.83A14.4,14.4,0,0,1,30,24.9a12.63,12.63,0,0,1-1.35-4.81V15.15a10.92,10.92,0,0,0-.16-1.79,7.44,7.44,0,0,1-2.24-.84,8.89,8.89,0,0,1,.4,2.64v4.94a14.24,14.24,0,0,0,1.65,5.85,16.17,16.17,0,0,0,2.44,3H5.13a16.17,16.17,0,0,0,2.44-3,14.24,14.24,0,0,0,1.65-5.85V15.15A8.8,8.8,0,0,1,18,6.31a8.61,8.61,0,0,1,4.76,1.44A7.49,7.49,0,0,1,22.5,6c0-.21,0-.42,0-.63a10.58,10.58,0,0,0-3.32-1V3.11a1.33,1.33,0,1,0-2.67,0V4.42A10.81,10.81,0,0,0,7.21,15.15v4.94A12.63,12.63,0,0,1,5.86,24.9a14.4,14.4,0,0,1-2.47,2.93,1,1,0,0,0-.34.75v1.36a1,1,0,0,0,1,1h27.8a1,1,0,0,0,1-1V28.58A1,1,0,0,0,32.51,27.83Z\"/>\n                <circle class=\"clr-i-outline--badged clr-i-outline-path-1--badged clr-i-badge\" cx=\"30\" cy=\"6\" r=\"5\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-1\" d=\"M32.85,28.13l-.34-.3A14.37,14.37,0,0,1,30,24.9a12.63,12.63,0,0,1-1.35-4.81V15.15A10.81,10.81,0,0,0,19.21,4.4V3.11a1.33,1.33,0,1,0-2.67,0V4.42A10.81,10.81,0,0,0,7.21,15.15v4.94A12.63,12.63,0,0,1,5.86,24.9a14.4,14.4,0,0,1-2.47,2.93l-.34.3v2.82H32.85Z\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-2\" d=\"M15.32,32a2.65,2.65,0,0,0,5.25,0Z\"/>\n                <path class=\"clr-i-solid--badged clr-i-solid-path-1--badged\" d=\"M18,34.28A2.67,2.67,0,0,0,20.58,32H15.32A2.67,2.67,0,0,0,18,34.28Z\"/>\n                <path class=\"clr-i-solid--badged clr-i-solid-path-2--badged\" d=\"M32.85,28.13l-.34-.3A14.37,14.37,0,0,1,30,24.9a12.63,12.63,0,0,1-1.35-4.81V15.15a10.92,10.92,0,0,0-.16-1.79A7.5,7.5,0,0,1,22.5,6c0-.21,0-.42,0-.63a10.57,10.57,0,0,0-3.32-1V3.11a1.33,1.33,0,1,0-2.67,0V4.42A10.81,10.81,0,0,0,7.21,15.15v4.94A12.63,12.63,0,0,1,5.86,24.9a14.4,14.4,0,0,1-2.47,2.93l-.34.3v2.82H32.85Z\"/>\n                <circle class=\"clr-i-solid--badged clr-i-solid-path-3--badged clr-i-badge\" cx=\"30\" cy=\"6\" r=\"5\"/>");
exports.ClrShapeImage = (0, svg_tag_generator_1.clrIconSVG)("<path d=\"M32,4H4A2,2,0,0,0,2,6V30a2,2,0,0,0,2,2H32a2,2,0,0,0,2-2V6A2,2,0,0,0,32,4ZM4,30V6H32V30Z\" class=\"clr-i-outline clr-i-outline-path-1\"/>\n            <path d=\"M8.92,14a3,3,0,1,0-3-3A3,3,0,0,0,8.92,14Zm0-4.6A1.6,1.6,0,1,1,7.33,11,1.6,1.6,0,0,1,8.92,9.41Z\" class=\"clr-i-outline clr-i-outline-path-2\"/>\n            <path d=\"M22.78,15.37l-5.4,5.4-4-4a1,1,0,0,0-1.41,0L5.92,22.9v2.83l6.79-6.79L16,22.18l-3.75,3.75H15l8.45-8.45L30,24V21.18l-5.81-5.81A1,1,0,0,0,22.78,15.37Z\" class=\"clr-i-outline clr-i-outline-path-3\"/>\n            <path d=\"M11.93,11a3,3,0,1,0-3,3A3,3,0,0,0,11.93,11Zm-4.6,0a1.6,1.6,0,1,1,1.6,1.6A1.6,1.6,0,0,1,7.33,11Z\" class=\"clr-i-outline--badged clr-i-outline-path-1--badged\"/>\n            <path d=\"M17.38,20.77l-4-4a1,1,0,0,0-1.41,0L5.92,22.9v2.83l6.79-6.79L16,22.18l-3.75,3.75H15l8.45-8.45L30,24V21.18l-5.81-5.81a1,1,0,0,0-1.41,0Z\" class=\"clr-i-outline--badged clr-i-outline-path-2--badged\"/>\n            <path d=\"M32,13.22V30H4V6H22.5a7.49,7.49,0,0,1,.28-2H4A2,2,0,0,0,2,6V30a2,2,0,0,0,2,2H32a2,2,0,0,0,2-2V12.34A7.45,7.45,0,0,1,32,13.22Z\" class=\"clr-i-outline--badged clr-i-outline-path-3--badged\"/>\n            <circle cx=\"30\" cy=\"6\" r=\"5\" class=\"clr-i-outline--badged clr-i-outline-path-4--badged clr-i-badge\"/>\n            <path d=\"M32,4H4A2,2,0,0,0,2,6V30a2,2,0,0,0,2,2H32a2,2,0,0,0,2-2V6A2,2,0,0,0,32,4ZM8.92,8a3,3,0,1,1-3,3A3,3,0,0,1,8.92,8ZM6,27V22.9l6-6.08a1,1,0,0,1,1.41,0L16,19.35,8.32,27Zm24,0H11.15l6.23-6.23,5.4-5.4a1,1,0,0,1,1.41,0L30,21.18Z\" class=\"clr-i-solid clr-i-solid-path-1\"/>\n            <path d=\"M30,13.5A7.48,7.48,0,0,1,22.78,4H4A2,2,0,0,0,2,6V30a2,2,0,0,0,2,2H32a2,2,0,0,0,2-2V12.34A7.46,7.46,0,0,1,30,13.5ZM8.92,8a3,3,0,1,1-3,3A3,3,0,0,1,8.92,8ZM6,27V22.9l6-6.08a1,1,0,0,1,1.41,0L16,19.35,8.32,27Zm24,0H11.15l6.23-6.23,5.4-5.4a1,1,0,0,1,1.41,0L30,21.18Z\" class=\"clr-i-solid--badged clr-i-solid-path-1--badged\"/>\n            <circle cx=\"30\" cy=\"6\" r=\"5\" class=\"clr-i-solid--badged clr-i-solid-path-2--badged clr-i-badge\"/>");
exports.ClrShapeCloud = (0, svg_tag_generator_1.clrIconSVG)("<path class=\"clr-i-outline clr-i-outline-path-1\" d=\"M27.14,33H10.62C5.67,33,1,28.19,1,23.1a10,10,0,0,1,8-9.75,10.19,10.19,0,0,1,20.33,1.06A10.07,10.07,0,0,1,29,16.66a8.29,8.29,0,0,1,6,8C35,29.1,31.33,33,27.14,33ZM19.09,6.23a8.24,8.24,0,0,0-8.19,8l0,.87-.86.1A7.94,7.94,0,0,0,3,23.1c0,4,3.77,7.9,7.62,7.9H27.14C30.21,31,33,28,33,24.65a6.31,6.31,0,0,0-5.37-6.26l-1.18-.18.39-1.13A8.18,8.18,0,0,0,19.09,6.23Z\"/>\n                <path class=\"clr-i-outline--badged clr-i-outline-path-1--badged\" d=\"M29,16.66a10.07,10.07,0,0,0,.25-2.24c0-.33,0-.65,0-1a7.45,7.45,0,0,1-2.1-.54,8,8,0,0,1-.3,4.16l-.39,1.13,1.18.18a6.31,6.31,0,0,1,5.37,6.26C32.95,28,30.16,31,27.09,31H10.57c-3.84,0-7.62-3.91-7.62-7.9a7.94,7.94,0,0,1,7-7.89l.86-.1,0-.87a8.24,8.24,0,0,1,8.19-8A8.13,8.13,0,0,1,22.58,7a7.53,7.53,0,0,1-.08-1,7.51,7.51,0,0,1,.09-1.12A10.13,10.13,0,0,0,19,4.23,10.26,10.26,0,0,0,8.91,13.36a10,10,0,0,0-8,9.75c0,5.09,4.67,9.9,9.62,9.9H27.09c4.19,0,7.86-3.9,7.86-8.35A8.29,8.29,0,0,0,29,16.66Z\"/>\n                <circle class=\"clr-i-outline--badged clr-i-outline-path-2--badged clr-i-badge\" cx=\"30\" cy=\"6\" r=\"5\"/>\n                <path class=\"clr-i-outline--alerted clr-i-outline-path-1--alerted\" d=\"M29,16.66a10.14,10.14,0,0,0,.2-1.3h-2a8.28,8.28,0,0,1-.37,1.72l-.39,1.13,1.18.18a6.31,6.31,0,0,1,5.37,6.26C32.95,28,30.16,31,27.09,31H10.57c-3.84,0-7.62-3.91-7.62-7.9a7.94,7.94,0,0,1,7-7.89l.86-.1,0-.87A8.16,8.16,0,0,1,21,6.47l1-1.8A10.19,10.19,0,0,0,8.91,13.36a10,10,0,0,0-8,9.75c0,5.09,4.67,9.9,9.62,9.9H27.09c4.19,0,7.86-3.9,7.86-8.35A8.29,8.29,0,0,0,29,16.66Z\"/>\n                <path class=\"clr-i-outline--alerted clr-i-outline-path-2--alerted clr-i-alert\" d=\"M26.85,1.14,21.13,11A1.28,1.28,0,0,0,22.23,13H33.68A1.28,1.28,0,0,0,34.78,11L29.06,1.14A1.28,1.28,0,0,0,26.85,1.14Z\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-1\" d=\"M29,16.66a10.07,10.07,0,0,0,.25-2.24A10.19,10.19,0,0,0,8.91,13.36,10,10,0,0,0,1,23.1C1,28.19,5.62,33,10.57,33H27.09C31.28,33,35,29.1,35,24.65A8.29,8.29,0,0,0,29,16.66Z\"/>\n                <path class=\"clr-i-solid--badged clr-i-solid-path-1--badged\" d=\"M29,16.66a10.07,10.07,0,0,0,.25-2.24c0-.33,0-.65,0-1a7.44,7.44,0,0,1-6.6-8.58A10.13,10.13,0,0,0,19,4.23,10.26,10.26,0,0,0,8.91,13.36,10,10,0,0,0,1,23.1C1,28.19,5.62,33,10.57,33H27.09C31.28,33,35,29.1,35,24.65A8.29,8.29,0,0,0,29,16.66Z\"/>\n                <circle class=\"clr-i-solid--badged clr-i-solid-path-2--badged clr-i-badge\" cx=\"30\" cy=\"6\" r=\"5\"/>\n                <path class=\"clr-i-solid--alerted clr-i-solid-path-1--alerted\" d=\"M29,16.66a10.15,10.15,0,0,0,.2-1.26h-7A3.68,3.68,0,0,1,19,9.89l3-5.21A10.19,10.19,0,0,0,8.91,13.36,10,10,0,0,0,1,23.1C1,28.19,5.62,33,10.57,33H27.09C31.28,33,35,29.1,35,24.65A8.29,8.29,0,0,0,29,16.66Z\"/>\n                <path class=\"clr-i-solid--alerted clr-i-solid-path-2--alerted clr-i-alert\" d=\"M26.85,1.14,21.13,11A1.28,1.28,0,0,0,22.23,13H33.68A1.28,1.28,0,0,0,34.78,11L29.06,1.14A1.28,1.28,0,0,0,26.85,1.14Z\"/>");
exports.ClrShapeEllipsisHorizontal = (0, svg_tag_generator_1.clrIconSVG)("<circle cx=\"31.1\" cy=\"18\" r=\"2.9\" class=\"clr-i-outline clr-i-outline-path-1\" />\n            <circle cx=\"18\" cy=\"18\" r=\"2.9\" class=\"clr-i-outline clr-i-outline-path-2\" />\n            <circle cx=\"4.9\" cy=\"18\" r=\"2.9\" class=\"clr-i-outline clr-i-outline-path-3\" />\n            <circle cx=\"31.1\" cy=\"18\" r=\"2.9\" class=\"clr-i-outline--badged clr-i-outline-path-1--badged\" />\n            <circle cx=\"18\" cy=\"18\" r=\"2.9\" class=\"clr-i-outline--badged clr-i-outline-path-2--badged\" />\n            <circle cx=\"4.9\" cy=\"18\" r=\"2.9\" class=\"clr-i-outline--badged clr-i-outline-path-3--badged\" />\n            <circle cx=\"30\" cy=\"6\" r=\"5\"  class=\"clr-i-outline--badged clr-i-outline-path-4--badged clr-i-badge\" />");
exports.ClrShapeEllipsisVertical = (0, svg_tag_generator_1.clrIconSVG)("<circle cx=\"18\" cy=\"4.9\" r=\"2.9\" class=\"clr-i-outline clr-i-outline-path-1\" />\n            <circle cx=\"18\" cy=\"18\" r=\"2.9\" class=\"clr-i-outline clr-i-outline-path-2\" />\n            <circle cx=\"18\" cy=\"31.1\" r=\"2.9\" class=\"clr-i-outline clr-i-outline-path-3\" />\n            <circle cx=\"18\" cy=\"4.9\" r=\"2.9\" class=\"clr-i-outline--badged clr-i-outline-path-1--badged\" />\n            <circle cx=\"18\" cy=\"18\" r=\"2.9\" class=\"clr-i-outline--badged clr-i-outline-path-2--badged\" />\n            <circle cx=\"18\" cy=\"31.1\" r=\"2.9\" class=\"clr-i-outline--badged clr-i-outline-path-3--badged\" />\n            <circle cx=\"30\" cy=\"6\" r=\"5\"  class=\"clr-i-outline--badged clr-i-outline-path-4--badged clr-i-badge\" />");
exports.ClrShapeFilterGrid = (0, svg_tag_generator_1.clrIconSVG)("<path class=\"clr-i-outline clr-i-outline-path-1\" d=\"M15,25.86l2,1V20.27a1,1,0,0,0-.29-.7L10.23,13H25.79l-6.47,6.57a1,1,0,0,0-.29.7L19,28l2,1V20.68L27.58,14A1.46,1.46,0,0,0,28,13V12a1,1,0,0,0-1-1H9a1,1,0,0,0-1,1v1a1.46,1.46,0,0,0,.42,1L15,20.68Z\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-1\" d=\"M8,11v1.12a.5.5,0,0,0,.15.35l7.28,7.36a.5.5,0,0,1,.15.35v6.89a.5.5,0,0,0,.28.45l3.95,1.41a.5.5,0,0,0,.72-.45l0-8.39a.54.54,0,0,1,.18-.35l7.12-7.25a.5.5,0,0,0,.15-.35V11Z\"/>");
exports.ClrShapeFilterGridCircle = (0, svg_tag_generator_1.clrIconSVG)("<path class=\"clr-i-outline clr-i-outline-path-1\" d=\"M15,25.86l2,1V20.27a1,1,0,0,0-.29-.7L10.23,13H25.79l-6.47,6.57a1,1,0,0,0-.29.7L19,28l2,1V20.68L27.58,14A1.46,1.46,0,0,0,28,13V12a1,1,0,0,0-1-1H9a1,1,0,0,0-1,1v1a1.46,1.46,0,0,0,.42,1L15,20.68Z\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-2\" d=\"M18,2A16,16,0,1,0,34,18,16,16,0,0,0,18,2Zm0,30A14,14,0,1,1,32,18,14,14,0,0,1,18,32Z\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-1\" d=\"M18,2A16,16,0,1,0,34,18,16,16,0,0,0,18,2Zm0,30A14,14,0,1,1,32,18,14,14,0,0,1,18,32Z\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-2\" d=\"M8,11v1.12a.5.5,0,0,0,.15.35l7.28,7.36a.5.5,0,0,1,.15.35v6.89a.5.5,0,0,0,.28.45l3.95,1.41a.5.5,0,0,0,.72-.45l0-8.39a.54.54,0,0,1,.18-.35l7.12-7.25a.5.5,0,0,0,.15-.35V11Z\"/>");
exports.ClrShapeVmBug = (0, svg_tag_generator_1.clrIconSVG)("<rect width=\"36\" height=\"36\" rx=\"3\" fill=\"#ffffff\" opacity=\"0.15\" style=\"isolation:isolate\"/><path d=\"M3.79,14.83a1.09,1.09,0,0,0-1.47-.56,1.09,1.09,0,0,0-.54,1.49l2.47,5.4c.39.85.8,1.29,1.57,1.29S7,22,7.39,21.16l2.17-4.77a.33.33,0,0,1,.31-.2.35.35,0,0,1,.35.35v4.61a1.15,1.15,0,0,0,1.14,1.3,1.17,1.17,0,0,0,1.17-1.3V17.38a1.15,1.15,0,0,1,1.22-1.2,1.13,1.13,0,0,1,1.18,1.2v3.77a1.17,1.17,0,1,0,2.32,0V17.38a1.15,1.15,0,0,1,1.22-1.2,1.13,1.13,0,0,1,1.18,1.2v3.77a1.16,1.16,0,1,0,2.31,0V16.86a2.69,2.69,0,0,0-2.78-2.69,3.57,3.57,0,0,0-2.47,1.05,2.75,2.75,0,0,0-2.38-1.05A3.93,3.93,0,0,0,12,15.22a2.82,2.82,0,0,0-2.08-1.05A2.55,2.55,0,0,0,7.4,15.89L5.82,19.63l-2-4.8\" fill=\"#ffffff\"/><path d=\"M33,14.18A1.14,1.14,0,0,0,31.9,15l-1.19,3.73L29.5,15.05a1.18,1.18,0,0,0-1.15-.87h-.1a1.2,1.2,0,0,0-1.15.87l-1.19,3.71-1.18-3.71a1.15,1.15,0,0,0-1.11-.87,1.08,1.08,0,0,0-1.12,1.07,1.68,1.68,0,0,0,.1.54l2,5.7a1.27,1.27,0,0,0,1.27,1,1.24,1.24,0,0,0,1.2-.93l1.2-3.64,1.2,3.64a1.25,1.25,0,0,0,1.26.93A1.27,1.27,0,0,0,32,21.5L34,15.73a1.77,1.77,0,0,0,.08-.48A1.07,1.07,0,0,0,33,14.18Z\" fill=\"#ffffff\"/>");
exports.ClrShapeSearch = (0, svg_tag_generator_1.clrIconSVG)("<path class=\"clr-i-outline clr-i-outline-path-1\" d=\"M16.33,5.05A10.95,10.95,0,1,1,5.39,16,11,11,0,0,1,16.33,5.05m0-2.05a13,13,0,1,0,13,13,13,13,0,0,0-13-13Z\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-2\" d=\"M35,33.29l-7.37-7.42-1.42,1.41,7.37,7.42A1,1,0,1,0,35,33.29Z\"/>");
exports.ClrShapeViewColumns = (0, svg_tag_generator_1.clrIconSVG)("<path class=\"clr-i-outline clr-i-outline-path-1\" d=\"M31,5H5A2,2,0,0,0,3,7V29a2,2,0,0,0,2,2H31a2,2,0,0,0,2-2V7A2,2,0,0,0,31,5ZM13,29H5V7h8Zm10,0H15V7h8Z\"/>");
exports.ClrShapeAngleDouble = (0, svg_tag_generator_1.clrIconSVG)("<path class=\"clr-i-outline clr-i-outline-path-1\" d=\"M29,19.41a1,1,0,0,1-.71-.29L18,8.83,7.71,19.12a1,1,0,0,1-1.41-1.41L18,6,29.71,17.71A1,1,0,0,1,29,19.41Z\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-2\" d=\"M29,30.41a1,1,0,0,1-.71-.29L18,19.83,7.71,30.12a1,1,0,0,1-1.41-1.41L18,17,29.71,28.71A1,1,0,0,1,29,30.41Z\"/>");
exports.ClrShapeCalendar = (0, svg_tag_generator_1.clrIconSVG)("<path class=\"clr-i-outline clr-i-outline-path-1\" d=\"M32.25,6H29V8h3V30H4V8H7V6H3.75A1.78,1.78,0,0,0,2,7.81V30.19A1.78,1.78,0,0,0,3.75,32h28.5A1.78,1.78,0,0,0,34,30.19V7.81A1.78,1.78,0,0,0,32.25,6Z\"/>\n                <rect class=\"clr-i-outline clr-i-outline-path-2\" x=\"8\" y=\"14\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline clr-i-outline-path-3\" x=\"14\" y=\"14\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline clr-i-outline-path-4\" x=\"20\" y=\"14\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline clr-i-outline-path-5\" x=\"26\" y=\"14\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline clr-i-outline-path-6\" x=\"8\" y=\"19\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline clr-i-outline-path-7\" x=\"14\" y=\"19\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline clr-i-outline-path-8\" x=\"20\" y=\"19\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline clr-i-outline-path-9\" x=\"26\" y=\"19\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline clr-i-outline-path-10\" x=\"8\" y=\"24\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline clr-i-outline-path-11\" x=\"14\" y=\"24\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline clr-i-outline-path-12\" x=\"20\" y=\"24\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline clr-i-outline-path-13\" x=\"26\" y=\"24\" width=\"2\" height=\"2\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-14\" d=\"M10,10a1,1,0,0,0,1-1V3A1,1,0,0,0,9,3V9A1,1,0,0,0,10,10Z\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-15\" d=\"M26,10a1,1,0,0,0,1-1V3a1,1,0,0,0-2,0V9A1,1,0,0,0,26,10Z\"/>\n                <rect class=\"clr-i-outline clr-i-outline-path-16\" x=\"13\" y=\"6\" width=\"10\" height=\"2\"/>\n                <path class=\"clr-i-outline--badged clr-i-outline-path-1--badged\" d=\"M32,13.22V30H4V8H7V6H3.75A1.78,1.78,0,0,0,2,7.81V30.19A1.78,1.78,0,0,0,3.75,32h28.5A1.78,1.78,0,0,0,34,30.19V12.34A7.45,7.45,0,0,1,32,13.22Z\"/>\n                <rect class=\"clr-i-outline--badged clr-i-outline-path-2--badged\" x=\"8\" y=\"14\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline--badged clr-i-outline-path-3--badged\" x=\"14\" y=\"14\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline--badged clr-i-outline-path-4--badged\" x=\"20\" y=\"14\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline--badged clr-i-outline-path-5--badged\" x=\"26\" y=\"14\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline--badged clr-i-outline-path-6--badged\" x=\"8\" y=\"19\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline--badged clr-i-outline-path-7--badged\" x=\"14\" y=\"19\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline--badged clr-i-outline-path-8--badged\" x=\"20\" y=\"19\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline--badged clr-i-outline-path-9--badged\" x=\"26\" y=\"19\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline--badged clr-i-outline-path-10--badged\" x=\"8\" y=\"24\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline--badged clr-i-outline-path-11--badged\" x=\"14\" y=\"24\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline--badged clr-i-outline-path-12--badged\" x=\"20\" y=\"24\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline--badged clr-i-outline-path-13--badged\" x=\"26\" y=\"24\" width=\"2\" height=\"2\"/>\n                <path class=\"clr-i-outline--badged clr-i-outline-path-14--badged\" d=\"M10,10a1,1,0,0,0,1-1V3A1,1,0,0,0,9,3V9A1,1,0,0,0,10,10Z\"/>\n                <path class=\"clr-i-outline--badged clr-i-outline-path-15--badged\" d=\"M22.5,6H13V8h9.78A7.49,7.49,0,0,1,22.5,6Z\"/>\n                <circle class=\"clr-i-outline--badged clr-i-outline-path-16--badged clr-i-badge\" cx=\"30\" cy=\"6\" r=\"5\"/>\n                <path class=\"clr-i-outline--alerted clr-i-outline-path-1--alerted\" d=\"M33.68,15.4H32V30H4V8H7V6H3.75A1.78,1.78,0,0,0,2,7.81V30.19A1.78,1.78,0,0,0,3.75,32h28.5A1.78,1.78,0,0,0,34,30.19V15.38Z\"/>\n                <rect class=\"clr-i-outline--alerted clr-i-outline-path-2--alerted\" x=\"8\" y=\"14\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline--alerted clr-i-outline-path-3--alerted\" x=\"14\" y=\"14\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline--alerted clr-i-outline-path-4--alerted\" x=\"8\" y=\"19\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline--alerted clr-i-outline-path-5--alerted\" x=\"14\" y=\"19\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline--alerted clr-i-outline-path-6--alerted\" x=\"20\" y=\"19\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline--alerted clr-i-outline-path-7--alerted\" x=\"26\" y=\"19\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline--alerted clr-i-outline-path-8--alerted\" x=\"8\" y=\"24\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline--alerted clr-i-outline-path-9--alerted\" x=\"14\" y=\"24\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline--alerted clr-i-outline-path-10--alerted\" x=\"20\" y=\"24\" width=\"2\" height=\"2\"/>\n                <rect class=\"clr-i-outline--alerted clr-i-outline-path-11--alerted\" x=\"26\" y=\"24\" width=\"2\" height=\"2\"/>\n                <path class=\"clr-i-outline--alerted clr-i-outline-path-12--alerted\" d=\"M10,10a1,1,0,0,0,1-1V3A1,1,0,0,0,9,3V9A1,1,0,0,0,10,10Z\"/><polygon points=\"21.29 6 13 6 13 8 20.14 8 21.29 6\"/>\n                <path class=\"clr-i-outline--alerted clr-i-outline-path-13--alerted clr-i-alert\" d=\"M26.85,1.14,21.13,11A1.28,1.28,0,0,0,22.23,13H33.68A1.28,1.28,0,0,0,34.78,11L29.06,1.14A1.28,1.28,0,0,0,26.85,1.14Z\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-1\" d=\"M32.25,6h-4V9a2.2,2.2,0,1,1-4.4,0V6H12.2V9A2.2,2.2,0,0,1,7.8,9V6h-4A1.78,1.78,0,0,0,2,7.81V30.19A1.78,1.78,0,0,0,3.75,32h28.5A1.78,1.78,0,0,0,34,30.19V7.81A1.78,1.78,0,0,0,32.25,6ZM10,26H8V24h2Zm0-5H8V19h2Zm0-5H8V14h2Zm6,10H14V24h2Zm0-5H14V19h2Zm0-5H14V14h2Zm6,10H20V24h2Zm0-5H20V19h2Zm0-5H20V14h2Zm6,10H26V24h2Zm0-5H26V19h2Zm0-5H26V14h2Z\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-2\" d=\"M10,10a1,1,0,0,0,1-1V3A1,1,0,0,0,9,3V9A1,1,0,0,0,10,10Z\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-3\" d=\"M26,10a1,1,0,0,0,1-1V3a1,1,0,0,0-2,0V9A1,1,0,0,0,26,10Z\"/>\n                <path class=\"clr-i-solid--badged clr-i-solid-path-1--badged\" d=\"M10,10a1,1,0,0,0,1-1V3A1,1,0,0,0,9,3V9A1,1,0,0,0,10,10Z\"/>\n                <path class=\"clr-i-solid--badged clr-i-solid-path-2--badged\" d=\"M30,13.5A7.5,7.5,0,0,1,22.5,6H12.2V9A2.2,2.2,0,0,1,7.8,9V6h-4A1.78,1.78,0,0,0,2,7.81V30.19A1.78,1.78,0,0,0,3.75,32h28.5A1.78,1.78,0,0,0,34,30.19V12.34A7.45,7.45,0,0,1,30,13.5ZM10,26H8V24h2Zm0-5H8V19h2Zm0-5H8V14h2Zm6,10H14V24h2Zm0-5H14V19h2Zm0-5H14V14h2Zm6,10H20V24h2Zm0-5H20V19h2Zm0-5H20V14h2Zm6,10H26V24h2Zm0-5H26V19h2Zm0-5H26V14h2Z\"/>\n                <circle class=\"clr-i-solid--badged clr-i-solid-path-3--badged clr-i-badge\" cx=\"30\" cy=\"6\" r=\"5\"/>\n                <path class=\"clr-i-solid--alerted clr-i-solid-path-1--alerted\" d=\"M33.68,15.4H22.23A3.68,3.68,0,0,1,19,9.89L21.29,6H12.2V9A2.2,2.2,0,0,1,7.8,9V6h-4A1.78,1.78,0,0,0,2,7.81V30.19A1.78,1.78,0,0,0,3.75,32h28.5A1.78,1.78,0,0,0,34,30.19V15.38ZM10,26H8V24h2Zm0-5H8V19h2Zm0-5H8V14h2Zm6,10H14V24h2Zm0-5H14V19h2Zm0-5H14V14h2Zm6,10H20V24h2Zm0-5H20V19h2Zm6,5H26V24h2Zm0-5H26V19h2Z\"/>\n                <path class=\"clr-i-solid--alerted clr-i-solid-path-2--alerted\" d=\"M10,10a1,1,0,0,0,1-1V3A1,1,0,0,0,9,3V9A1,1,0,0,0,10,10Z\"/>\n                <path class=\"clr-i-solid--alerted clr-i-solid-path-3--alerted clr-i-alert\" d=\"M26.85,1.14,21.13,11A1.28,1.28,0,0,0,22.23,13H33.68A1.28,1.28,0,0,0,34.78,11L29.06,1.14A1.28,1.28,0,0,0,26.85,1.14Z\"/>");
exports.ClrShapeEvent = (0, svg_tag_generator_1.clrIconSVG)("<path class=\"clr-i-outline clr-i-outline-path-1\" d=\"M16.17,25.86,10.81,20.5a1,1,0,0,1,1.41-1.41L16.17,23l8.64-8.64a1,1,0,0,1,1.41,1.41Z\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-2\" d=\"M32.25,6H29V8h3V30H4V8H7V6H3.75A1.78,1.78,0,0,0,2,7.81V30.19A1.78,1.78,0,0,0,3.75,32h28.5A1.78,1.78,0,0,0,34,30.19V7.81A1.78,1.78,0,0,0,32.25,6Z\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-3\" d=\"M10,10a1,1,0,0,0,1-1V3A1,1,0,0,0,9,3V9A1,1,0,0,0,10,10Z\"/>\n                <path class=\"clr-i-outline clr-i-outline-path-4\" d=\"M26,10a1,1,0,0,0,1-1V3a1,1,0,0,0-2,0V9A1,1,0,0,0,26,10Z\"/>\n                <rect class=\"clr-i-outline clr-i-outline-path-5\" x=\"13\" y=\"6\" width=\"10\" height=\"2\"/>\n                <path class=\"clr-i-outline--badged clr-i-outline-path-1--badged\" d=\"M10.81,20.5l5.36,5.36L26.22,15.81a1,1,0,0,0-1.41-1.41L16.17,23l-3.94-3.94a1,1,0,0,0-1.41,1.41Z\"/>\n                <path class=\"clr-i-outline--badged clr-i-outline-path-2--badged\" d=\"M10,10a1,1,0,0,0,1-1V3A1,1,0,0,0,9,3V9A1,1,0,0,0,10,10Z\"/>\n                <path class=\"clr-i-outline--badged clr-i-outline-path-3--badged\" d=\"M32,13.22V30H4V8H7V6H3.75A1.78,1.78,0,0,0,2,7.81V30.19A1.78,1.78,0,0,0,3.75,32h28.5A1.78,1.78,0,0,0,34,30.19V12.34A7.45,7.45,0,0,1,32,13.22Z\"/>\n                <path class=\"clr-i-outline--badged clr-i-outline-path-4--badged\" d=\"M22.5,6H13V8h9.78A7.49,7.49,0,0,1,22.5,6Z\"/>\n                <circle class=\"clr-i-outline--badged clr-i-outline-path-5--badged clr-i-badge\" cx=\"30\" cy=\"6\" r=\"5\"/>\n                <path class=\"clr-i-outline--alerted clr-i-outline-path-1--alerted\" d=\"M10,10a1,1,0,0,0,1-1V3A1,1,0,0,0,9,3V9A1,1,0,0,0,10,10Z\"/>\n                <path class=\"clr-i-outline--alerted clr-i-outline-path-2--alerted\" d=\"M10.81,20.5l5.36,5.36L26.22,15.81a1,1,0,0,0,.23-.41H23.8L16.17,23l-3.94-3.94a1,1,0,0,0-1.41,1.41Z\"/>\n                <polygon class=\"clr-i-outline--alerted clr-i-outline-path-3--alerted\" points=\"21.29 6 13 6 13 8 20.14 8 21.29 6\"/>\n                <path class=\"clr-i-outline--alerted clr-i-outline-path-4--alerted\" d=\"M33.68,15.4H32V30H4V8H7V6H3.75A1.78,1.78,0,0,0,2,7.81V30.19A1.78,1.78,0,0,0,3.75,32h28.5A1.78,1.78,0,0,0,34,30.19V15.38Z\"/>\n                <path class=\"clr-i-outline--alerted clr-i-outline-path-5--alerted clr-i-alert\" d=\"M26.85,1.14,21.13,11A1.28,1.28,0,0,0,22.23,13H33.68A1.28,1.28,0,0,0,34.78,11L29.06,1.14A1.28,1.28,0,0,0,26.85,1.14Z\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-1\" d=\"M10,10a1,1,0,0,0,1-1V3A1,1,0,0,0,9,3V9A1,1,0,0,0,10,10Z\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-2\" d=\"M26,10a1,1,0,0,0,1-1V3a1,1,0,0,0-2,0V9A1,1,0,0,0,26,10Z\"/>\n                <path class=\"clr-i-solid clr-i-solid-path-3\" d=\"M32.25,6h-4V9a2.2,2.2,0,0,1-4.4,0V6H12.2V9A2.2,2.2,0,0,1,7.8,9V6h-4A1.78,1.78,0,0,0,2,7.81V30.19A1.78,1.78,0,0,0,3.75,32h28.5A1.78,1.78,0,0,0,34,30.19V7.81A1.78,1.78,0,0,0,32.25,6ZM25.94,16.58l-9.67,9.67L11,20.94A1.36,1.36,0,0,1,12.9,19l3.38,3.38L24,14.66a1.36,1.36,0,1,1,1.93,1.93Z\"/>\n                <path class=\"clr-i-solid--alerted clr-i-solid-path-1--alerted\" d=\"M10,10a1,1,0,0,0,1-1V3A1,1,0,0,0,9,3V9A1,1,0,0,0,10,10Z\"/>\n                <path class=\"clr-i-solid--alerted clr-i-solid-path-2--alerted\" d=\"M33.68,15.4H26.3a1.34,1.34,0,0,1-.36,1.18l-9.67,9.67L11,20.94A1.36,1.36,0,0,1,12.9,19l3.38,3.38,7-7h-1A3.68,3.68,0,0,1,19,9.89L21.29,6H12.2V9A2.2,2.2,0,0,1,7.8,9V6h-4A1.78,1.78,0,0,0,2,7.81V30.19A1.78,1.78,0,0,0,3.75,32h28.5A1.78,1.78,0,0,0,34,30.19V15.38Z\"/>\n                <path class=\"clr-i-solid--alerted clr-i-solid-path-3--alerted clr-i-alert\" d=\"M26.85,1.14,21.13,11A1.28,1.28,0,0,0,22.23,13H33.68A1.28,1.28,0,0,0,34.78,11L29.06,1.14A1.28,1.28,0,0,0,26.85,1.14Z\"/>\n                <path class=\"clr-i-solid--badged clr-i-solid-path-1--badged\" d=\"M10,10a1,1,0,0,0,1-1V3A1,1,0,0,0,9,3V9A1,1,0,0,0,10,10Z\"/>\n                <path class=\"clr-i-solid--badged clr-i-solid-path-2--badged\" d=\"M30,13.5A7.5,7.5,0,0,1,22.5,6H12.2V9A2.2,2.2,0,0,1,7.8,9V6h-4A1.78,1.78,0,0,0,2,7.81V30.19A1.78,1.78,0,0,0,3.75,32h28.5A1.78,1.78,0,0,0,34,30.19V12.34A7.45,7.45,0,0,1,30,13.5Zm-4.06,3.08-9.67,9.67L11,20.94A1.36,1.36,0,0,1,12.9,19l3.38,3.38L24,14.66a1.36,1.36,0,1,1,1.93,1.93Z\"/>\n                <circle class=\"clr-i-solid--badged clr-i-solid-path-3--badged clr-i-badge\" cx=\"30\" cy=\"6\" r=\"5\"/>");
exports.ClrShapeEye = (0, svg_tag_generator_1.clrIconSVG)("<path d=\"M33.62,17.53c-3.37-6.23-9.28-10-15.82-10S5.34,11.3,2,17.53L1.72,18l.26.48c3.37,6.23,9.28,10,15.82,10s12.46-3.72,15.82-10l.26-.48ZM17.8,26.43C12.17,26.43,7,23.29,4,18c3-5.29,8.17-8.43,13.8-8.43S28.54,12.72,31.59,18C28.54,23.29,23.42,26.43,17.8,26.43Z\" class=\"clr-i-outline clr-i-outline-path-1\"/>\n            <path d=\"M18.09,11.17A6.86,6.86,0,1,0,25,18,6.86,6.86,0,0,0,18.09,11.17Zm0,11.72A4.86,4.86,0,1,1,23,18,4.87,4.87,0,0,1,18.09,22.89Z\" class=\"clr-i-outline clr-i-outline-path-2\"/>\n            <path d=\"M33.62,17.53c-3.37-6.23-9.28-10-15.82-10S5.34,11.3,2,17.53L1.72,18l.26.48c3.37,6.23,9.28,10,15.82,10s12.46-3.72,15.82-10l.26-.48ZM17.8,26.43C12.17,26.43,7,23.29,4,18c3-5.29,8.17-8.43,13.8-8.43S28.54,12.72,31.59,18C28.54,23.29,23.42,26.43,17.8,26.43Z\" class=\"clr-i-solid clr-i-solid-path-1\"/>\n            <circle cx=\"18.09\" cy=\"18.03\" r=\"6.86\" class=\"clr-i-solid clr-i-solid-path-2\"/>");
exports.ClrShapeEyeHide = (0, svg_tag_generator_1.clrIconSVG)("<path d=\"M25.19,20.4A6.78,6.78,0,0,0,25.62,18a6.86,6.86,0,0,0-6.86-6.86,6.79,6.79,0,0,0-2.37.43L18,13.23a4.78,4.78,0,0,1,.74-.06A4.87,4.87,0,0,1,23.62,18a4.79,4.79,0,0,1-.06.74Z\" class=\"clr-i-outline clr-i-outline-path-1\"/>\n            <path d=\"M34.29,17.53c-3.37-6.23-9.28-10-15.82-10a16.82,16.82,0,0,0-5.24.85L14.84,10a14.78,14.78,0,0,1,3.63-.47c5.63,0,10.75,3.14,13.8,8.43a17.75,17.75,0,0,1-4.37,5.1l1.42,1.42a19.93,19.93,0,0,0,5-6l.26-.48Z\" class=\"clr-i-outline clr-i-outline-path-2\"/>\n            <path d=\"M4.87,5.78l4.46,4.46a19.52,19.52,0,0,0-6.69,7.29L2.38,18l.26.48c3.37,6.23,9.28,10,15.82,10a16.93,16.93,0,0,0,7.37-1.69l5,5,1.75-1.5-26-26Zm9.75,9.75,6.65,6.65a4.81,4.81,0,0,1-2.5.72A4.87,4.87,0,0,1,13.9,18,4.81,4.81,0,0,1,14.62,15.53Zm-1.45-1.45a6.85,6.85,0,0,0,9.55,9.55l1.6,1.6a14.91,14.91,0,0,1-5.86,1.2c-5.63,0-10.75-3.14-13.8-8.43a17.29,17.29,0,0,1,6.12-6.3Z\" class=\"clr-i-outline clr-i-outline-path-3\"/>\n            <path d=\"M18.37,11.17A6.79,6.79,0,0,0,16,11.6l8.8,8.8A6.78,6.78,0,0,0,25.23,18,6.86,6.86,0,0,0,18.37,11.17Z\" class=\"clr-i-solid clr-i-solid-path-1\"/>\n            <path d=\"M34.29,17.53c-3.37-6.23-9.28-10-15.82-10a16.82,16.82,0,0,0-5.24.85L14.84,10a14.78,14.78,0,0,1,3.63-.47c5.63,0,10.75,3.14,13.8,8.43a17.75,17.75,0,0,1-4.37,5.1l1.42,1.42a19.93,19.93,0,0,0,5-6l.26-.48Z\" class=\"clr-i-solid clr-i-solid-path-2\"/>\n            <path d=\"M4.87,5.78l4.46,4.46a19.52,19.52,0,0,0-6.69,7.29L2.38,18l.26.48c3.37,6.23,9.28,10,15.82,10a16.93,16.93,0,0,0,7.37-1.69l5,5,1.75-1.5-26-26Zm8.3,8.3a6.85,6.85,0,0,0,9.55,9.55l1.6,1.6a14.91,14.91,0,0,1-5.86,1.2c-5.63,0-10.75-3.14-13.8-8.43a17.29,17.29,0,0,1,6.12-6.3Z\" class=\"clr-i-solid clr-i-solid-path-3\"/>");
exports.ClrShapeStepForward2 = (0, svg_tag_generator_1.clrIconSVG)("<path d=\"M7.08,6.52a1.68,1.68,0,0,0,0,2.4L16.51,18,7.12,27.08a1.7,1.7,0,0,0,2.36,2.44h0L21.4,18,9.48,6.47A1.69,1.69,0,0,0,7.08,6.52Z\" class=\"clr-i-outline clr-i-outline-path-1\" /><path d=\"M26.49,5a1.7,1.7,0,0,0-1.7,1.7V29.3a1.7,1.7,0,0,0,3.4,0V6.7A1.7,1.7,0,0,0,26.49,5Z\" class=\"clr-i-outline clr-i-outline-path-2\" />");
exports.ClrShapeArrow = (0, svg_tag_generator_1.clrIconSVG)("<path d=\"M27.66,15.61,18,6,8.34,15.61A1,1,0,1,0,9.75,17L17,9.81V28.94a1,1,0,1,0,2,0V9.81L26.25,17a1,1,0,0,0,1.41-1.42Z\" class=\"clr-i-outline clr-i-outline-path-1\"/>");
exports.CoreShapes = {
    'unknown-status': exports.ClrShapeUnknownStatus,
    home: exports.ClrShapeHome,
    cog: exports.ClrShapeCog,
    check: exports.ClrShapeCheck,
    times: exports.ClrShapeTimes,
    'exclamation-triangle': exports.ClrShapeExclamationTriangle,
    'exclamation-circle': exports.ClrShapeExclamationCircle,
    'check-circle': exports.ClrShapeCheckCircle,
    'info-circle': exports.ClrShapeInfoCircle,
    'info-standard': exports.ClrShapeInfoStandard,
    'success-standard': exports.ClrShapeSuccessStandard,
    'error-standard': exports.ClrShapeErrorStandard,
    'warning-standard': exports.ClrShapeWarningStandard,
    'help-info': exports.ClrShapeHelpInfo,
    bars: exports.ClrShapeBars,
    user: exports.ClrShapeUser,
    angle: exports.ClrShapeAngle,
    folder: exports.ClrShapeFolder,
    'folder-open': exports.ClrShapeFolderOpen,
    bell: exports.ClrShapeBell,
    image: exports.ClrShapeImage,
    cloud: exports.ClrShapeCloud,
    'ellipsis-horizontal': exports.ClrShapeEllipsisHorizontal,
    'ellipsis-vertical': exports.ClrShapeEllipsisVertical,
    'filter-grid': exports.ClrShapeFilterGrid,
    'filter-grid-circle': exports.ClrShapeFilterGridCircle,
    'vm-bug': exports.ClrShapeVmBug,
    search: exports.ClrShapeSearch,
    'view-columns': exports.ClrShapeViewColumns,
    'angle-double': exports.ClrShapeAngleDouble,
    calendar: exports.ClrShapeCalendar,
    event: exports.ClrShapeEvent,
    eye: exports.ClrShapeEye,
    'eye-hide': exports.ClrShapeEyeHide,
    'step-forward-2': exports.ClrShapeStepForward2,
    arrow: exports.ClrShapeArrow,
};
Object.defineProperty(exports.CoreShapes, 'house', (0, descriptor_config_1.descriptorConfig)(exports.CoreShapes.home));
Object.defineProperty(exports.CoreShapes, 'settings', (0, descriptor_config_1.descriptorConfig)(exports.CoreShapes.cog));
Object.defineProperty(exports.CoreShapes, 'success', (0, descriptor_config_1.descriptorConfig)(exports.CoreShapes.check));
Object.defineProperty(exports.CoreShapes, 'close', (0, descriptor_config_1.descriptorConfig)(exports.CoreShapes.times));
Object.defineProperty(exports.CoreShapes, 'warning', (0, descriptor_config_1.descriptorConfig)(exports.CoreShapes['exclamation-triangle']));
Object.defineProperty(exports.CoreShapes, 'error', (0, descriptor_config_1.descriptorConfig)(exports.CoreShapes['exclamation-circle']));
Object.defineProperty(exports.CoreShapes, 'info', (0, descriptor_config_1.descriptorConfig)(exports.CoreShapes['info-circle']));
Object.defineProperty(exports.CoreShapes, 'menu', (0, descriptor_config_1.descriptorConfig)(exports.CoreShapes.bars));
Object.defineProperty(exports.CoreShapes, 'avatar', (0, descriptor_config_1.descriptorConfig)(exports.CoreShapes.user));
Object.defineProperty(exports.CoreShapes, 'caret', (0, descriptor_config_1.descriptorConfig)(exports.CoreShapes.angle));
Object.defineProperty(exports.CoreShapes, 'directory', (0, descriptor_config_1.descriptorConfig)(exports.CoreShapes.folder));
Object.defineProperty(exports.CoreShapes, 'notification', (0, descriptor_config_1.descriptorConfig)(exports.CoreShapes.bell));
Object.defineProperty(exports.CoreShapes, 'collapse', (0, descriptor_config_1.descriptorConfig)(exports.CoreShapes['angle-double']));


/***/ }),

/***/ "./projects/icons/src/utils/descriptor-config.ts":
/*!*******************************************************!*\
  !*** ./projects/icons/src/utils/descriptor-config.ts ***!
  \*******************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

/*
 * Copyright (c) 2016-2021 VMware, Inc. All Rights Reserved.
 * This software is released under MIT license.
 * The full license information can be found in LICENSE in the root directory of this project.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.descriptorConfig = void 0;
function descriptorConfig(value) {
    return { enumerable: true, writable: true, configurable: true, value: value };
}
exports.descriptorConfig = descriptorConfig;


/***/ }),

/***/ "./projects/icons/src/utils/shape-template-observer.ts":
/*!*************************************************************!*\
  !*** ./projects/icons/src/utils/shape-template-observer.ts ***!
  \*************************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
exports.ShapeTemplateObserver = exports.changeHandlerCallbacks = void 0;
exports.changeHandlerCallbacks = {};
var ShapeTemplateObserver = /** @class */ (function () {
    function ShapeTemplateObserver() {
        this.callbacks = exports.changeHandlerCallbacks;
    }
    Object.defineProperty(ShapeTemplateObserver, "instance", {
        get: function () {
            if (!ShapeTemplateObserver.singleInstance) {
                ShapeTemplateObserver.singleInstance = new ShapeTemplateObserver();
            }
            return ShapeTemplateObserver.singleInstance;
        },
        enumerable: false,
        configurable: true
    });
    ShapeTemplateObserver.prototype.subscribeTo = function (shapeName, changeHandlerCallback) {
        var _this = this;
        if (!this.callbacks[shapeName]) {
            this.callbacks[shapeName] = [changeHandlerCallback];
        }
        else {
            if (this.callbacks[shapeName].indexOf(changeHandlerCallback) === -1) {
                this.callbacks[shapeName].push(changeHandlerCallback);
            }
        }
        // this returned function give users an ability to remove the subscription
        return function () {
            var removeAt = _this.callbacks[shapeName].indexOf(changeHandlerCallback);
            _this.callbacks[shapeName].splice(removeAt, 1);
            // if the array is empty, remove the property from the callbacks
            if (_this.callbacks[shapeName].length === 0) {
                delete _this.callbacks[shapeName];
            }
        };
    };
    ShapeTemplateObserver.prototype.emitChanges = function (shapeName, template) {
        if (this.callbacks[shapeName]) {
            // this will emit changes to all observers
            // by calling their callback functions on template changes
            this.callbacks[shapeName].map(function (changeHandlerCallback) {
                changeHandlerCallback(template);
            });
        }
    };
    return ShapeTemplateObserver;
}());
exports.ShapeTemplateObserver = ShapeTemplateObserver;


/***/ }),

/***/ "./projects/icons/src/utils/svg-tag-generator.ts":
/*!*******************************************************!*\
  !*** ./projects/icons/src/utils/svg-tag-generator.ts ***!
  \*******************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

/*
 * Copyright (c) 2016-2021 VMware, Inc. All Rights Reserved.
 * This software is released under MIT license.
 * The full license information can be found in LICENSE in the root directory of this project.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.clrIconSVG = void 0;
var BADGED_CLASS_SUBSTRING = '--badged';
var ALERTED_CLASS_SUBSTRING = '--alerted';
var SOLID_CLASS = 'clr-i-solid';
function clrIconSVG(content) {
    var classes = '';
    if (content.indexOf(BADGED_CLASS_SUBSTRING) > -1) {
        classes += 'can-badge ';
    }
    if (content.indexOf(ALERTED_CLASS_SUBSTRING) > -1) {
        classes += 'can-alert ';
    }
    if (content.indexOf(SOLID_CLASS) > -1) {
        classes += 'has-solid ';
    }
    var openingTag;
    if (classes) {
        openingTag = "<svg version=\"1.1\" class=\"" + classes + "\" viewBox=\"0 0 36 36\" preserveAspectRatio=\"xMidYMid meet\"\n    xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" focusable=\"false\" role=\"img\">";
    }
    else {
        openingTag = "<svg version=\"1.1\" viewBox=\"0 0 36 36\" preserveAspectRatio=\"xMidYMid meet\"\n    xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" focusable=\"false\" role=\"img\">";
    }
    var closingTag = "</svg>";
    return openingTag + content + closingTag;
}
exports.clrIconSVG = clrIconSVG;


/***/ })

/******/ });
});
//# sourceMappingURL=index.js.map