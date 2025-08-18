import { should } from '@paulmillr/jsbt/test.js';
import './aes.test.ts';
import './arx.test.ts';
import './basic.test.ts';
import './crosstest.test.ts';
import './ff1.test.ts';
import './polyval.test.ts';
import './utils.test.ts';
import './webcrypto.test.ts';
// import './errors.test.ts';

should.runWhen(import.meta.url);
