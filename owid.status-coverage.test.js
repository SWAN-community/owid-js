/* ****************************************************************************
 * Copyright 2026 51 Degrees Mobile Experts Limited (51degrees.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 * ***************************************************************************/

// A status nobody tests is a status nobody has seen work. Every member of
// both vocabularies must therefore either be produced by the library and
// asserted by a test, or say in the source that nothing produces it and why,
// so that a reader meeting the member finds the answer where the member is
// rather than in a pull request nobody will read again.
//
// These tests read the source rather than run it, so adding a member without
// either a test or the explanation fails the build.

const fs = require('fs');
const path = require('path');
const owid = require('./v1');

// The phrase a member carries when nothing in the library produces it. The
// explanation of why follows it in the same comment.
const cannotBeProduced = "Nothing produces this";

const source = fs.readFileSync(path.join(__dirname, 'v1.js'), 'utf8');

const testSources = fs.readdirSync(__dirname)
    .filter(f => f.endsWith('.test.js') && f !== path.basename(__filename))
    .map(f => fs.readFileSync(path.join(__dirname, f), 'utf8'))
    .join('\n');

/**
 * The lines of the frozen object literal that declares the vocabulary named,
 * so a member and the comment above it can be found together.
 * @param {string} name - ParseStatus or SignatureStatus.
 * @returns {string[]} the lines of the declaration.
 */
function declarationLines(name) {
    var start = source.indexOf('const ' + name + ' = Object.freeze({');
    expect(start).toBeGreaterThan(-1);
    var end = source.indexOf('});', start);
    expect(end).toBeGreaterThan(start);
    return source.substring(start, end).split('\n');
}

/**
 * The comment written immediately above a member, being the run of comment
 * lines that ends at its declaration.
 * @param {string} name - ParseStatus or SignatureStatus.
 * @param {string} member - the member.
 * @returns {string} the comment.
 */
function commentFor(name, member) {
    var lines = declarationLines(name);
    var at = lines.findIndex(l => l.trim().indexOf(member + ':') === 0);
    expect(at).toBeGreaterThan(-1);
    var comment = [];
    for (var i = at - 1; i >= 0; i--) {
        var line = lines[i].trim();
        if (line.indexOf('//') !== 0) { break; }
        comment.unshift(line);
    }
    return comment.join(' ');
}

/**
 * How many times the library produces the member, counting every mention of
 * it outside its own declaration.
 * @param {string} name - ParseStatus or SignatureStatus.
 * @param {string} member - the member.
 * @returns {number} the count.
 */
function producedCount(name, member) {
    var uses = source.split(name + '.' + member).length - 1;
    // A member whose name is a prefix of no other member counts exactly, and
    // none of them is, so the split is the count.
    return uses;
}

/**
 * How many times the rest of the test suite asserts the member.
 * @param {string} name - ParseStatus or SignatureStatus.
 * @param {string} member - the member.
 * @returns {number} the count.
 */
function assertedCount(name, member) {
    return testSources.split(name + '.' + member).length - 1;
}

const vocabularies = [
    ['ParseStatus', Object.keys(owid.ParseStatus)],
    ['SignatureStatus', Object.keys(owid.SignatureStatus)]
];

// Nothing here is inferred from the report or the pull request. The two
// counts and the comment are all read from the files in this repository.
vocabularies.forEach(([name, members]) => {

    test(name + ' declares the cross language vocabulary', () => {
        expect(members.length).toBeGreaterThan(0);
        members.forEach(m => {
            expect(typeof owid[name][m]).toBe('string');
        });
        expect(Object.isFrozen(owid[name])).toBe(true);
    });

    members.forEach(member => {
        test(name + '.' + member + ' is either tested or explained', () => {
            var produced = producedCount(name, member);
            var explained =
                commentFor(name, member).indexOf(cannotBeProduced) !== -1;

            if (explained) {
                // A member that says nothing produces it must have no test
                // claiming otherwise, or the comment is untrue. Whether the
                // source names it at all is a separate matter, because one
                // of them is named by a guard that no input can reach, and
                // reading the file cannot tell reachable from unreachable.
                expect(assertedCount(name, member)).toBe(0);
                return;
            }

            // Everything else must be produced by the library and asserted
            // by a test, or it has never been seen to work.
            expect(produced).toBeGreaterThan(0);
            expect(assertedCount(name, member)).toBeGreaterThan(0);
        });
    });
});

// The members that carry the explanation are named here as well, so a change
// that quietly adds or removes one shows up as a failure rather than as a
// silently shorter list.
test('only the members that cannot be produced carry the explanation', () => {
    var explained = [];
    vocabularies.forEach(([name, members]) => {
        members.forEach(member => {
            if (commentFor(name, member).indexOf(cannotBeProduced) !== -1) {
                explained.push(name + '.' + member);
            }
        });
    });

    expect(explained.sort()).toEqual([
        'ParseStatus.MALFORMED_ENVELOPE',
        'SignatureStatus.IMPLEMENTATION_CAPACITY_EXCEEDED',
        'SignatureStatus.INVALID_SIGNATURE_LENGTH'
    ]);
});
