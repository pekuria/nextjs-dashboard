"use strict";
var __makeTemplateObject = (this && this.__makeTemplateObject) || function (cooked, raw) {
    if (Object.defineProperty) { Object.defineProperty(cooked, "raw", { value: raw }); } else { cooked.raw = raw; }
    return cooked;
};
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
exports.__esModule = true;
exports.getUser = exports.fetchFilteredCustomers = exports.fetchCustomers = exports.fetchInvoiceById = exports.fetchInvoicesPages = exports.fetchFilteredInvoices = exports.fetchCardData = exports.fetchLatestInvoices = exports.fetchRevenue = void 0;
var postgres_1 = require("@vercel/postgres");
var utils_1 = require("./utils");
var cache_1 = require("next/cache");
function fetchRevenue() {
    return __awaiter(this, void 0, void 0, function () {
        var data, error_1;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    cache_1.unstable_noStore();
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 4, , 5]);
                    // Artificially delay a response for demo purposes.
                    // Don't do this in production :)
                    console.log('Fetching revenue data...');
                    return [4 /*yield*/, new Promise(function (resolve) { return setTimeout(resolve, 3000); })];
                case 2:
                    _a.sent();
                    return [4 /*yield*/, postgres_1.sql(templateObject_1 || (templateObject_1 = __makeTemplateObject(["SELECT * FROM revenue"], ["SELECT * FROM revenue"])))];
                case 3:
                    data = _a.sent();
                    console.log('Data fetch completed after 3 seconds.');
                    return [2 /*return*/, data.rows];
                case 4:
                    error_1 = _a.sent();
                    console.error('Database Error:', error_1);
                    throw new Error('Failed to fetch revenue data.');
                case 5: return [2 /*return*/];
            }
        });
    });
}
exports.fetchRevenue = fetchRevenue;
function fetchLatestInvoices() {
    return __awaiter(this, void 0, void 0, function () {
        var data, latestInvoices, error_2;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    cache_1.unstable_noStore();
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 4, , 5]);
                    return [4 /*yield*/, new Promise(function (resolve) { return setTimeout(resolve, 3000); })];
                case 2:
                    _a.sent();
                    return [4 /*yield*/, postgres_1.sql(templateObject_2 || (templateObject_2 = __makeTemplateObject(["\n      SELECT invoices.amount, customers.name, customers.image_url, customers.email, invoices.id\n      FROM invoices\n      JOIN customers ON invoices.customer_id = customers.id\n      ORDER BY invoices.date DESC\n      LIMIT 5"], ["\n      SELECT invoices.amount, customers.name, customers.image_url, customers.email, invoices.id\n      FROM invoices\n      JOIN customers ON invoices.customer_id = customers.id\n      ORDER BY invoices.date DESC\n      LIMIT 5"])))];
                case 3:
                    data = _a.sent();
                    latestInvoices = data.rows.map(function (invoice) { return (__assign(__assign({}, invoice), { amount: utils_1.formatCurrency(invoice.amount) })); });
                    return [2 /*return*/, latestInvoices];
                case 4:
                    error_2 = _a.sent();
                    console.error('Database Error:', error_2);
                    throw new Error('Failed to fetch the latest invoices.');
                case 5: return [2 /*return*/];
            }
        });
    });
}
exports.fetchLatestInvoices = fetchLatestInvoices;
function fetchCardData() {
    var _a, _b, _c, _d;
    return __awaiter(this, void 0, void 0, function () {
        var invoiceCountPromise, customerCountPromise, invoiceStatusPromise, data, numberOfInvoices, numberOfCustomers, totalPaidInvoices, totalPendingInvoices, error_3;
        return __generator(this, function (_e) {
            switch (_e.label) {
                case 0:
                    cache_1.unstable_noStore();
                    _e.label = 1;
                case 1:
                    _e.trys.push([1, 4, , 5]);
                    return [4 /*yield*/, new Promise(function (resolve) { return setTimeout(resolve, 3000); })];
                case 2:
                    _e.sent();
                    invoiceCountPromise = postgres_1.sql(templateObject_3 || (templateObject_3 = __makeTemplateObject(["SELECT COUNT(*) FROM invoices"], ["SELECT COUNT(*) FROM invoices"])));
                    customerCountPromise = postgres_1.sql(templateObject_4 || (templateObject_4 = __makeTemplateObject(["SELECT COUNT(*) FROM customers"], ["SELECT COUNT(*) FROM customers"])));
                    invoiceStatusPromise = postgres_1.sql(templateObject_5 || (templateObject_5 = __makeTemplateObject(["SELECT\n         SUM(CASE WHEN status = 'paid' THEN amount ELSE 0 END) AS \"paid\",\n         SUM(CASE WHEN status = 'pending' THEN amount ELSE 0 END) AS \"pending\"\n         FROM invoices"], ["SELECT\n         SUM(CASE WHEN status = 'paid' THEN amount ELSE 0 END) AS \"paid\",\n         SUM(CASE WHEN status = 'pending' THEN amount ELSE 0 END) AS \"pending\"\n         FROM invoices"])));
                    return [4 /*yield*/, Promise.all([
                            invoiceCountPromise,
                            customerCountPromise,
                            invoiceStatusPromise,
                        ])];
                case 3:
                    data = _e.sent();
                    numberOfInvoices = Number((_a = data[0].rows[0].count) !== null && _a !== void 0 ? _a : '0');
                    numberOfCustomers = Number((_b = data[1].rows[0].count) !== null && _b !== void 0 ? _b : '0');
                    totalPaidInvoices = utils_1.formatCurrency((_c = data[2].rows[0].paid) !== null && _c !== void 0 ? _c : '0');
                    totalPendingInvoices = utils_1.formatCurrency((_d = data[2].rows[0].pending) !== null && _d !== void 0 ? _d : '0');
                    return [2 /*return*/, {
                            numberOfCustomers: numberOfCustomers,
                            numberOfInvoices: numberOfInvoices,
                            totalPaidInvoices: totalPaidInvoices,
                            totalPendingInvoices: totalPendingInvoices
                        }];
                case 4:
                    error_3 = _e.sent();
                    console.error('Database Error:', error_3);
                    throw new Error('Failed to fetch card data.');
                case 5: return [2 /*return*/];
            }
        });
    });
}
exports.fetchCardData = fetchCardData;
var ITEMS_PER_PAGE = 6;
function fetchFilteredInvoices(query, currentPage) {
    return __awaiter(this, void 0, void 0, function () {
        var offset, invoices, error_4;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    cache_1.unstable_noStore();
                    offset = (currentPage - 1) * ITEMS_PER_PAGE;
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, , 4]);
                    return [4 /*yield*/, postgres_1.sql(templateObject_6 || (templateObject_6 = __makeTemplateObject(["\n      SELECT\n        invoices.id,\n        invoices.amount,\n        invoices.date,\n        invoices.status,\n        customers.name,\n        customers.email,\n        customers.image_url\n      FROM invoices\n      JOIN customers ON invoices.customer_id = customers.id\n      WHERE\n        customers.name ILIKE ", " OR\n        customers.email ILIKE ", " OR\n        invoices.amount::text ILIKE ", " OR\n        invoices.date::text ILIKE ", " OR\n        invoices.status ILIKE ", "\n      ORDER BY invoices.date DESC\n      LIMIT ", " OFFSET ", "\n    "], ["\n      SELECT\n        invoices.id,\n        invoices.amount,\n        invoices.date,\n        invoices.status,\n        customers.name,\n        customers.email,\n        customers.image_url\n      FROM invoices\n      JOIN customers ON invoices.customer_id = customers.id\n      WHERE\n        customers.name ILIKE ", " OR\n        customers.email ILIKE ", " OR\n        invoices.amount::text ILIKE ", " OR\n        invoices.date::text ILIKE ", " OR\n        invoices.status ILIKE ", "\n      ORDER BY invoices.date DESC\n      LIMIT ", " OFFSET ", "\n    "])), "%" + query + "%", "%" + query + "%", "%" + query + "%", "%" + query + "%", "%" + query + "%", ITEMS_PER_PAGE, offset)];
                case 2:
                    invoices = _a.sent();
                    return [2 /*return*/, invoices.rows];
                case 3:
                    error_4 = _a.sent();
                    console.error('Database Error:', error_4);
                    throw new Error('Failed to fetch invoices.');
                case 4: return [2 /*return*/];
            }
        });
    });
}
exports.fetchFilteredInvoices = fetchFilteredInvoices;
function fetchInvoicesPages(query) {
    return __awaiter(this, void 0, void 0, function () {
        var count, totalPages, error_5;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    cache_1.unstable_noStore();
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, , 4]);
                    return [4 /*yield*/, postgres_1.sql(templateObject_7 || (templateObject_7 = __makeTemplateObject(["SELECT COUNT(*)\n    FROM invoices\n    JOIN customers ON invoices.customer_id = customers.id\n    WHERE\n      customers.name ILIKE ", " OR\n      customers.email ILIKE ", " OR\n      invoices.amount::text ILIKE ", " OR\n      invoices.date::text ILIKE ", " OR\n      invoices.status ILIKE ", "\n  "], ["SELECT COUNT(*)\n    FROM invoices\n    JOIN customers ON invoices.customer_id = customers.id\n    WHERE\n      customers.name ILIKE ", " OR\n      customers.email ILIKE ", " OR\n      invoices.amount::text ILIKE ", " OR\n      invoices.date::text ILIKE ", " OR\n      invoices.status ILIKE ", "\n  "])), "%" + query + "%", "%" + query + "%", "%" + query + "%", "%" + query + "%", "%" + query + "%")];
                case 2:
                    count = _a.sent();
                    totalPages = Math.ceil(Number(count.rows[0].count) / ITEMS_PER_PAGE);
                    return [2 /*return*/, totalPages];
                case 3:
                    error_5 = _a.sent();
                    console.error('Database Error:', error_5);
                    throw new Error('Failed to fetch total number of invoices.');
                case 4: return [2 /*return*/];
            }
        });
    });
}
exports.fetchInvoicesPages = fetchInvoicesPages;
function fetchInvoiceById(id) {
    return __awaiter(this, void 0, void 0, function () {
        var data, invoice, error_6;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    cache_1.unstable_noStore();
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, , 4]);
                    return [4 /*yield*/, postgres_1.sql(templateObject_8 || (templateObject_8 = __makeTemplateObject(["\n      SELECT\n        invoices.id,\n        invoices.customer_id,\n        invoices.amount,\n        invoices.status\n      FROM invoices\n      WHERE invoices.id = ", ";\n    "], ["\n      SELECT\n        invoices.id,\n        invoices.customer_id,\n        invoices.amount,\n        invoices.status\n      FROM invoices\n      WHERE invoices.id = ", ";\n    "])), id)];
                case 2:
                    data = _a.sent();
                    invoice = data.rows.map(function (invoice) { return (__assign(__assign({}, invoice), { 
                        // Convert amount from cents to dollars
                        amount: invoice.amount / 100 })); });
                    return [2 /*return*/, invoice[0]];
                case 3:
                    error_6 = _a.sent();
                    console.error('Database Error:', error_6);
                    throw new Error('Failed to fetch invoice.');
                case 4: return [2 /*return*/];
            }
        });
    });
}
exports.fetchInvoiceById = fetchInvoiceById;
function fetchCustomers() {
    return __awaiter(this, void 0, void 0, function () {
        var data, customers, err_1;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    cache_1.unstable_noStore();
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, , 4]);
                    return [4 /*yield*/, postgres_1.sql(templateObject_9 || (templateObject_9 = __makeTemplateObject(["\n      SELECT\n        id,\n        name\n      FROM customers\n      ORDER BY name ASC\n    "], ["\n      SELECT\n        id,\n        name\n      FROM customers\n      ORDER BY name ASC\n    "])))];
                case 2:
                    data = _a.sent();
                    customers = data.rows;
                    return [2 /*return*/, customers];
                case 3:
                    err_1 = _a.sent();
                    console.error('Database Error:', err_1);
                    throw new Error('Failed to fetch all customers.');
                case 4: return [2 /*return*/];
            }
        });
    });
}
exports.fetchCustomers = fetchCustomers;
function fetchFilteredCustomers(query) {
    return __awaiter(this, void 0, void 0, function () {
        var data, customers, err_2;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    cache_1.unstable_noStore();
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, , 4]);
                    return [4 /*yield*/, postgres_1.sql(templateObject_10 || (templateObject_10 = __makeTemplateObject(["\n\t\tSELECT\n\t\t  customers.id,\n\t\t  customers.name,\n\t\t  customers.email,\n\t\t  customers.image_url,\n\t\t  COUNT(invoices.id) AS total_invoices,\n\t\t  SUM(CASE WHEN invoices.status = 'pending' THEN invoices.amount ELSE 0 END) AS total_pending,\n\t\t  SUM(CASE WHEN invoices.status = 'paid' THEN invoices.amount ELSE 0 END) AS total_paid\n\t\tFROM customers\n\t\tLEFT JOIN invoices ON customers.id = invoices.customer_id\n\t\tWHERE\n\t\t  customers.name ILIKE ", " OR\n        customers.email ILIKE ", "\n\t\tGROUP BY customers.id, customers.name, customers.email, customers.image_url\n\t\tORDER BY customers.name ASC\n\t  "], ["\n\t\tSELECT\n\t\t  customers.id,\n\t\t  customers.name,\n\t\t  customers.email,\n\t\t  customers.image_url,\n\t\t  COUNT(invoices.id) AS total_invoices,\n\t\t  SUM(CASE WHEN invoices.status = 'pending' THEN invoices.amount ELSE 0 END) AS total_pending,\n\t\t  SUM(CASE WHEN invoices.status = 'paid' THEN invoices.amount ELSE 0 END) AS total_paid\n\t\tFROM customers\n\t\tLEFT JOIN invoices ON customers.id = invoices.customer_id\n\t\tWHERE\n\t\t  customers.name ILIKE ", " OR\n        customers.email ILIKE ", "\n\t\tGROUP BY customers.id, customers.name, customers.email, customers.image_url\n\t\tORDER BY customers.name ASC\n\t  "])), "%" + query + "%", "%" + query + "%")];
                case 2:
                    data = _a.sent();
                    customers = data.rows.map(function (customer) { return (__assign(__assign({}, customer), { total_pending: utils_1.formatCurrency(customer.total_pending), total_paid: utils_1.formatCurrency(customer.total_paid) })); });
                    return [2 /*return*/, customers];
                case 3:
                    err_2 = _a.sent();
                    console.error('Database Error:', err_2);
                    throw new Error('Failed to fetch customer table.');
                case 4: return [2 /*return*/];
            }
        });
    });
}
exports.fetchFilteredCustomers = fetchFilteredCustomers;
function getUser(email) {
    return __awaiter(this, void 0, void 0, function () {
        var user, error_7;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    cache_1.unstable_noStore();
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, , 4]);
                    return [4 /*yield*/, postgres_1.sql(templateObject_11 || (templateObject_11 = __makeTemplateObject(["SELECT * FROM users WHERE email=", ""], ["SELECT * FROM users WHERE email=", ""])), email)];
                case 2:
                    user = _a.sent();
                    return [2 /*return*/, user.rows[0]];
                case 3:
                    error_7 = _a.sent();
                    console.error('Failed to fetch user:', error_7);
                    throw new Error('Failed to fetch user.');
                case 4: return [2 /*return*/];
            }
        });
    });
}
exports.getUser = getUser;
var templateObject_1, templateObject_2, templateObject_3, templateObject_4, templateObject_5, templateObject_6, templateObject_7, templateObject_8, templateObject_9, templateObject_10, templateObject_11;
