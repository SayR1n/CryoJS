var math = require('./math/multiply');
var addLib = require('./math/add');

console.log('=== CryoJS Test ===');

var sum = addLib.add(3, 7);
console.log('3 + 7 =', sum);

var product = math.multiply(6, 7);
console.log('6 * 7 =', product);

var math2 = require('./math/multiply');
console.log('Cached module same ref:', math === math2);

var greet = (function() {
    var prefix = 'Hello';
    return function(name) {
        return prefix + ', ' + name + '!';
    };
})();

['World', 'CryoJS', 'Duktape'].forEach(function(name) {
    console.log(greet(name));
});

console.log('Done.');
