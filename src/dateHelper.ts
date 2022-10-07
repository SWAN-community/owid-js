/* ****************************************************************************
 * Copyright 2021 51 Degrees Mobile Experts Limited (51degrees.com)
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

import { Io } from './io';

export class DateHelper {

    // The base date and time as a number on milliseconds.
    private static readonly ioDateBaseTime = Io.dateBase.getTime();

    // Number of minutes in milliseconds.
    private static readonly minuteInMs = 1000 * 60;

    /**
     * getDateInMinutes returns the number of minutes that have elapsed since the ioDateBase epoch.
     * @param date to be fetched in minutes
     * @returns the number of minutes that elapsed between the epoch and the date
     */
    public static getDateInMinutes(date: Date): number {
        const difference = date.getTime() - DateHelper.ioDateBaseTime;
        return difference / DateHelper.minuteInMs;
    }

    /**
     * getTimeFromMinutes returns the date time from the minutes provided.
     * @param minutes that have elapsed since the epoch.
     * @returns the date
     */
    public static getDateFromMinutes(minutes: number): Date {
        return new Date(DateHelper.ioDateBaseTime + (minutes * DateHelper.minuteInMs));
    }
}