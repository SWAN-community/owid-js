import { Io } from '../src/io';
import { OWID, OWIDTarget } from '../src/owid';

/**
 * Test class used with the OWID features.
 */
export class Data implements OWIDTarget {

    // Test value to be included in the data associated with the OWID.
    public value: string;

    // Instance of the OWID related to the data.
    public owid: OWID<Data>;

    // Needed to get the data that is signed along with the OWID domain and timestamp.
    public addOwidData(buffer: number[]) {
        Io.writeString(buffer, this.value);
    }
}