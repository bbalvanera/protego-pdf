/**
 * Copyright (C) 2018 Bernardo Balvanera
 *
 * This file is part of ProtegoPdf.
 *
 * ProtegoPdf is a free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

import * as gulp from 'gulp';
import * as pug from 'gulp-pug';
import * as plumber from 'gulp-plumber';

function buildPug() {
  return gulp.src('src/**/*.pug')
    .pipe(plumber(function (error) {
       console.log(error.message);
    }))
    .pipe(pug({
      doctype: 'html',
      pretty: true
    }))
    .pipe(gulp.dest('src'));
}

export = buildPug;
