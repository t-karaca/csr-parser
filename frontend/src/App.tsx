import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table";
import { CsrDetailsModel } from "@/models";
import clsx from "clsx";
import { UploadIcon } from "lucide-react";
import { ChangeEvent, useCallback, useEffect, useRef, useState } from "react";

interface ParseError {
    status?: number;
    statusText?: string;
    message?: string;
}

function App() {
    const [isCustomParser, setIsCustomParser] = useState(false);
    const [showDropzone, setShowDropzone] = useState(false);
    const [file, setFile] = useState<File | null>(null);
    const [csrDetails, setCsrDetails] = useState<CsrDetailsModel | null>(null);
    const [error, setError] = useState<ParseError | null>(null);

    const fileInputRef = useRef<HTMLInputElement>(null);

    // initialize file drag and drop
    useEffect(() => {
        let dragCounter = 0;

        const dragEnter = () => {
            dragCounter++;
        };

        const dragLeave = () => {
            dragCounter--;
            if (dragCounter == 0) {
                setShowDropzone(false);
            }
        };

        const dragOver = (e: DragEvent) => {
            setShowDropzone(true);
            e.preventDefault();
        };

        const drop = (e: DragEvent) => {
            dragCounter = 0;
            setShowDropzone(false);
            e.preventDefault();

            if (e.dataTransfer) {
                const fileList = e.dataTransfer.files;

                if (fileList.length > 0) {
                    setFile(fileList.item(0));
                }
            }
        };

        document.addEventListener("dragenter", dragEnter);
        document.addEventListener("dragleave", dragLeave);
        document.addEventListener("dragover", dragOver);
        document.addEventListener("drop", drop);

        return () => {
            document.removeEventListener("dragenter", dragEnter);
            document.removeEventListener("dragleave", dragLeave);
            document.removeEventListener("dragover", dragOver);
            document.removeEventListener("drop", drop);
        };
    }, []);

    useEffect(() => {
        if (!file) {
            return;
        }

        async function request() {
            try {
                const response = await fetch("/api/v1/csr", { method: "POST", body: file });
                const json = await response.json();

                if (response.ok) {
                    setCsrDetails(json as CsrDetailsModel);
                    setError(null);
                } else {
                    setCsrDetails(null);
                    setError({
                        status: response.status,
                        statusText: response.statusText,
                        message: json.error,
                    });
                }
            } catch (e) {
                // error is either json parse error because of dev server proxy responding with 500 empty response body
                // or a network error

                setCsrDetails(null);
                setError({
                    message: "API not available",
                });
            }
        }

        request();
    }, [isCustomParser, file]);

    const onInputChange = useCallback((e: ChangeEvent<HTMLInputElement>) => {
        if (e.target.files && e.target.files.length > 0) {
            setFile(e.target.files.item(0));
        }
    }, []);

    return (
        <>
            <div className="container mx-auto py-20">
                <div className="flex flex-col gap-5 items-center">
                    <h1 className="text-3xl font-semibold text-center mb-8">PKCS#10 Parser</h1>
                    <input
                        ref={fileInputRef}
                        type="file"
                        className="hidden"
                        onChange={onInputChange}
                    />
                    <Button onClick={() => fileInputRef.current?.click()}>
                        <UploadIcon />
                        Pick a file ...
                    </Button>
                    <div>... or drag and drop a file into this window</div>
                    <div>PEM and DER files are supported</div>
                    <div className="flex flex-row items-center gap-3">
                        <Label className={clsx("transition", isCustomParser && "opacity-25")}>
                            BouncyCastle Parser
                        </Label>
                        <Switch checked={isCustomParser} onCheckedChange={setIsCustomParser} />
                        <Label className={clsx("transition", !isCustomParser && "opacity-25")}>
                            Custom Parser
                        </Label>
                    </div>
                    <Separator className="my-8" />
                    {!file && <div>No file selected</div>}
                    {file && <div>{file.name}</div>}
                    {error && (
                        <Alert variant="destructive">
                            <AlertTitle>
                                {error.status} {error.statusText}
                            </AlertTitle>
                            {error.message && <AlertDescription>{error.message}</AlertDescription>}
                        </Alert>
                    )}
                    {csrDetails && (
                        <Table>
                            <TableBody>
                                <TableRow>
                                    <TableCell>Signature Algorithm</TableCell>
                                    <TableCell>
                                        {csrDetails.signatureAlgorithm}
                                        {csrDetails.signatureAlgorithmId !==
                                            csrDetails.signatureAlgorithm && (
                                            <span> ({csrDetails.signatureAlgorithmId})</span>
                                        )}
                                    </TableCell>
                                </TableRow>
                                <TableRow>
                                    <TableCell>Public Key Algorithm</TableCell>
                                    <TableCell>
                                        {csrDetails.publicKeyAlgorithm}
                                        {csrDetails.publicKeyAlgorithmId !==
                                            csrDetails.publicKeyAlgorithm && (
                                            <span> ({csrDetails.publicKeyAlgorithmId})</span>
                                        )}
                                    </TableCell>
                                </TableRow>
                                {csrDetails.rsaKeyLength && (
                                    <TableRow>
                                        <TableCell>RSA Key Length</TableCell>
                                        <TableCell>{csrDetails.rsaKeyLength}</TableCell>
                                    </TableRow>
                                )}
                                {csrDetails.commonName && (
                                    <TableRow>
                                        <TableCell>Common Name</TableCell>
                                        <TableCell>{csrDetails.commonName}</TableCell>
                                    </TableRow>
                                )}
                                {csrDetails.country && (
                                    <TableRow>
                                        <TableCell>Country</TableCell>
                                        <TableCell>{csrDetails.country}</TableCell>
                                    </TableRow>
                                )}
                                {csrDetails.locality && (
                                    <TableRow>
                                        <TableCell>Locality</TableCell>
                                        <TableCell>{csrDetails.locality}</TableCell>
                                    </TableRow>
                                )}
                                {csrDetails.stateOrProvince && (
                                    <TableRow>
                                        <TableCell>State or Province</TableCell>
                                        <TableCell>{csrDetails.stateOrProvince}</TableCell>
                                    </TableRow>
                                )}
                                {csrDetails.organizationName && (
                                    <TableRow>
                                        <TableCell>Organization Name</TableCell>
                                        <TableCell>{csrDetails.organizationName}</TableCell>
                                    </TableRow>
                                )}
                                {csrDetails.organizationUnit && (
                                    <TableRow>
                                        <TableCell>Organization Unit</TableCell>
                                        <TableCell>{csrDetails.organizationUnit}</TableCell>
                                    </TableRow>
                                )}
                                {csrDetails.subjectAlternativeName && (
                                    <TableRow>
                                        <TableCell>Subject Alternative Name</TableCell>
                                        <TableCell>{csrDetails.subjectAlternativeName}</TableCell>
                                    </TableRow>
                                )}
                                {csrDetails.emailAddress && (
                                    <TableRow>
                                        <TableCell>Email Address</TableCell>
                                        <TableCell>{csrDetails.emailAddress}</TableCell>
                                    </TableRow>
                                )}
                            </TableBody>
                        </Table>
                    )}
                </div>
            </div>
            {showDropzone && (
                <div className="absolute flex flex-col gap-3 items-center justify-center left-0 top-0 w-screen h-screen bg-white backdrop-blur bg-opacity-60">
                    <UploadIcon size={64} />
                    <span className="text-lg font-semibold">Drop file here</span>
                </div>
            )}
        </>
    );
}

export default App;
