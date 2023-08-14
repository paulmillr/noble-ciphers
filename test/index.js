const { should } = require('micro-should');
require('./basic.test.js');
require('./gcm.test.js');
require('./gcm-siv.test.js');
require('./ff1.test.js');

if (require.main === module) should.run();
