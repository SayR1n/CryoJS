var addModule = require('./add');

function multiply(a, b) {
    var result = 0;
    for (var i = 0; i < b; i++) {
        result = addModule.add(result, a);
    }
    return result;
}

module.exports = { multiply: multiply };
