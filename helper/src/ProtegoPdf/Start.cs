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

using Newtonsoft.Json;
using System;
using System.Threading.Tasks;

namespace ProtegoPdf
{
    class Start
    {
        static void Main()
        {
            var process = ProcessAsync();
            process.Wait();
        }

        static async Task ProcessAsync()
        {
            while (true) {
                // wait for something to arrive through stdin
                var input = await Console.In.ReadLineAsync();

                if (input.ToLower() == "exit")
                {
                    break;
                }

                await ProcessInput(input);
            }
        }

        private static async Task ProcessInput(string input) {

            if (!TryDeserializeInput(input, out PdfRequest request))
            {
                await Console.Error.WriteAsync("Invalid Request");
                return;
            }
            else if (!ValidRequest(request))
            {
                await Console.Error.WriteAsync($"Invalid request");
                return;
            }

            try
            {
                var command = new PdfCommand(request.Name);
                var result = await command.Execute(request.Options);

                await Console.Out.WriteAsync(result.ToJson());
            }
            catch (Exception ex)
            {
                await Console.Error.WriteAsync($"Unexpected exception ocurred: {ex.Message}");
                throw;
            }
        }

        private static bool TryDeserializeInput(string input, out PdfRequest output)
        {
            var retVal = true;

            try
            {
                output = JsonConvert.DeserializeObject<PdfRequest>(input);
            }
            catch (JsonReaderException)
            {
                output = null;
                retVal = false;
            }

            return retVal;
        }

        private static bool ValidRequest(PdfRequest request)
        {
            bool retVal = true;

            if (request == null)
            {
                retVal = false;
            }
            else if (request.Name == PdfCommandName.None)
            {
                retVal = false;
            }
            else if (request.Options == null || string.IsNullOrWhiteSpace(request.Options.Source))
            {
                retVal = false;
            }

            return retVal;
        }
    }
}
