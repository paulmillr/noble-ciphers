import { should } from 'micro-should';
import './aes.test.ts';
import './arx.test.ts';
import './basic.test.ts';
import './crosstest.test.ts';
import './ff1.test.ts';
import './polyval.test.ts';
import './utils.test.ts';

should.runWhen(import.meta.url);
