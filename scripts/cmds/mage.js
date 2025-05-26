const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');

const styles = ['KANDINSKY', 'UHD', 'ANIME', 'DEFAULT']; // Ensure 'KANDINSKY' matches your API's expected style names

async function generateKandinskiImage(prompt, options) {
    const AUTH_HEADERS = {
        'X-Key': 'Key 1189B3E57401F09E71C5500A18A18278',
        'X-Secret': 'Secret 440C6EA9A259ABB3CA50A14FE42E363C',
    };

    const formData = new FormData();

    // Fetch model ID dynamically
    const getModelId = async () => {
        try {
            const response = await axios.get('https://api-key.fusionbrain.ai/key/api/v1/models', { headers: AUTH_HEADERS });
            return response.data[0].id;
        } catch (error) {
            console.error("Error fetching model ID:", error.response ? error.response.data : error.message);
            throw new Error("Failed to fetch model ID");
        }
    };

    const modelId = await getModelId();

    const params = {
        type: "GENERATE",
        numImages: options.num || 1,
        width: options.width || 1024,
        height: options.height || 1024,
        style: styles[options.style || 0], // Ensure style index is within bounds
        generateParams: {
            query: prompt,
            negativePrompt: "",
        },
    };

    formData.append('model_id', modelId);
    formData.append('params', JSON.stringify(params), { contentType: 'application/json' });

    try {
        console.log("Sending request with params:", params);

        const response = await axios.post('https://api-key.fusionbrain.ai/key/api/v1/text2image/run', formData, {
            headers: {
                ...AUTH_HEADERS,
                ...formData.getHeaders(), // Ensure correct form-data headers
            },
        });

        console.log("Response data:", response.data);

        const { uuid } = response.data;
        if (!uuid) {
            throw new Error("Failed to start image generation");
        }

        // Poll for image generation status
        let attempts = 10;
        let statusResponse = null;
        while (attempts > 0) {
            statusResponse = await axios.get(`https://api-key.fusionbrain.ai/key/api/v1/text2image/status/${uuid}`, {
                headers: AUTH_HEADERS
            });
            console.log("Status response data:", statusResponse.data);

            const data = statusResponse.data;
            if (data.status === 'DONE') {
                const images = data.images;
                if (images && images.length > 0) {
                    return images.map(base64Image => Buffer.from(base64Image, 'base64'));
                } else {
                    throw new Error("No images generated or images were censored");
                }
            }

            await new Promise(resolve => setTimeout(resolve, 10000)); // Wait 10 seconds before retry
            attempts--;
        }

        throw new Error('Image generation timed out or failed');

    } catch (error) {
        console.error("Error generating image:", error.response ? error.response.data : error.message);
        const detailedErrorMessage = `Error generating image: ${error.message}\nResponse data: ${JSON.stringify(error.response ? error.response.data : "No response data", null, 2)}`;
        throw new Error(detailedErrorMessage);
    }
}

const aspectRatios = {
    "1:1": [512, 512],
    "16:9": [1024, 576],
    "9:16": [576, 1024],
    "3:2": [960, 640],
    "2:3": [640, 960],
};

function parseKandinskiOptions(args) {
    let options = {};
    args.forEach((arg, index) => {
        if (arg.startsWith("--num")) {
            options.num = Number(args[index + 1]);
        } else if (arg.startsWith("--ar")) {
            const ratio = args[index + 1];
            if (aspectRatios[ratio]) {
                [options.width, options.height] = aspectRatios[ratio];
            }
        } else if (arg.startsWith("--style")) {
            options.style = Number(args[index + 1]) - 1;  // Subtracting 1 to match array index
        }
    });
    return options;
}

module.exports = {
    config: {
        name: "Kandinski",
        aliases: ["mage"],
        version: "1.0",
        author: "Marrcus",
        countDown: 5,
        role: 0,
        longDescription: "Text to Image using Kandinski API",
        category: "ai",
        guide: {
            en: "{pn} prompt [--num number] [--ar ratio] [--style number]"
        }
    },

    onStart: async function({ api, args, message, event }) {
        try {
            let prompt = args.filter(arg => !arg.startsWith("--")).join(" ");
            let options = parseKandinskiOptions(args);

            const processingMessage = await message.reply("Please wait...⏳");
            message.reaction("⏳", event.messageID);

            const images = await generateKandinskiImage(prompt, options);
            if (images.length > 0) {
                await Promise.all(images.map(async (imageBuffer, index) => {
                    const filePath = path.join(__dirname, `generated_image_${index}.jpg`);
                    fs.writeFileSync(filePath, imageBuffer);

                    await message.reply({
                        body: `✅ Image Generated`,
                        attachment: fs.createReadStream(filePath)
                    });

                    fs.unlinkSync(filePath); // Remove the file after sending
                }));
            } else {
                throw new Error("No images generated");
            }

            message.unsend(processingMessage.messageID);
            await message.reaction("✅", event.messageID);
        } catch (error) {
            console.error(error);
            await message.reply(`An error occurred: ${error.message}`);
            message.reaction("❌", event.messageID);
        }
    }
};