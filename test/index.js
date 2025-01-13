import { should } from 'micro-should';
import './basic.test.js';
import './arx.test.js';
import './polyval.test.js';
import './aes.test.js';
import './ff1.test.js';
import './utils.test.js';
import './crosstest.test.js';

should.runWhen(import.meta.url);
